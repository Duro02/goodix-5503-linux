// SIGFM algorithm for libfprint

// Copyright (C) 2022 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (c) 2022 Natasha England-Elbro <ashenglandelbro@protonmail.com>
// Copyright (c) 2022 Timur Mangliev <tigrmango@gmail.com>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include "sigfm.hpp"
#include "img-info.hpp"

#include <algorithm>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tuple>
#include <utility>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/imgproc.hpp>

namespace {
constexpr auto distance_match = 0.85;
constexpr auto length_match = 0.05;
constexpr auto angle_match = 0.05;
constexpr std::size_t min_match = 5;
constexpr int sift_nfeatures = 256;
constexpr auto sift_octave_layers = 3;
constexpr auto sift_contrast_threshold = 0.04;
constexpr auto sift_edge_threshold = 18.0;
constexpr auto sift_sigma = 2.0;
constexpr std::size_t max_correspondences = 32;
constexpr double pi = 3.14159265358979323846;

void secure_wipe(void* buffer, std::size_t length)
{
    volatile unsigned char* cursor = static_cast<unsigned char*>(buffer);
    while (length-- > 0) {
        *cursor++ = 0;
    }
}

template<typename T>
struct SensitiveVector {
    std::vector<T> value;

    ~SensitiveVector()
    {
        if (!value.empty()) {
            secure_wipe(value.data(), value.size() * sizeof(T));
        }
    }
};

template<typename T>
struct SensitiveNestedVector {
    std::vector<std::vector<T>> value;

    ~SensitiveNestedVector()
    {
        for (auto& inner : value) {
            if (!inner.empty()) {
                secure_wipe(inner.data(), inner.size() * sizeof(T));
            }
        }
    }
};

struct SensitiveMat {
    cv::Mat value;

    ~SensitiveMat()
    {
        if (value.empty()) {
            return;
        }
        const std::size_t row_bytes = static_cast<std::size_t>(value.cols) * value.elemSize();
        for (int row = 0; row < value.rows; row++) {
            secure_wipe(value.ptr(row), row_bytes);
        }
    }
};

struct match {
    cv::Point2i p1;
    cv::Point2i p2;

    match(cv::Point2i ip1, cv::Point2i ip2) : p1{ip1}, p2{ip2} {}
    bool operator==(const match& right) const
    {
        return std::tie(p1, p2) == std::tie(right.p1, right.p2);
    }
};

struct angle {
    double cosine;
    double sine;
    match correspondences[2];

    angle(double cosine_, double sine_, match first, match second)
        : cosine{cosine_}, sine{sine_}, correspondences{first, second}
    {
    }
};

void wipe_info(SigfmImgInfo* info)
{
    if (info == nullptr) {
        return;
    }
    if (!info->descriptors.empty()) {
        const std::size_t row_bytes =
            static_cast<std::size_t>(info->descriptors.cols) * info->descriptors.elemSize();
        for (int row = 0; row < info->descriptors.rows; row++) {
            secure_wipe(info->descriptors.ptr(row), row_bytes);
        }
    }
    if (!info->keypoints.empty()) {
        secure_wipe(info->keypoints.data(),
                    info->keypoints.size() * sizeof(cv::KeyPoint));
    }
}
} // namespace

int sigfm_keypoints_count(SigfmImgInfo* info)
{
    if (info == nullptr || info->keypoints.size() > static_cast<std::size_t>(INT_MAX)) {
        return 0;
    }
    return static_cast<int>(info->keypoints.size());
}

SigfmImgInfo* sigfm_extract(const SigfmPix* pix, int width, int height)
{
    if (pix == nullptr || width <= 0 || height <= 0 ||
        static_cast<std::size_t>(width) > SIZE_MAX / static_cast<std::size_t>(height)) {
        return nullptr;
    }

    try {
        SensitiveMat image;
        SensitiveMat enhanced;
        SensitiveMat descriptors;
        SensitiveVector<cv::KeyPoint> keypoints;

        keypoints.value.reserve (sift_nfeatures);
        image.value.create(height, width, CV_8UC1);
        std::memcpy(image.value.data, pix,
                    static_cast<std::size_t>(width) * static_cast<std::size_t>(height));

        auto clahe = cv::createCLAHE(4.0, cv::Size(4, 4));
        clahe->apply(image.value, enhanced.value);
        const cv::Mat roi = cv::Mat::ones(enhanced.value.size(), CV_8UC1);
        cv::SIFT::create(sift_nfeatures,
                         sift_octave_layers,
                         sift_contrast_threshold,
                         sift_edge_threshold,
                         sift_sigma)
            ->detectAndCompute(enhanced.value, roi, keypoints.value,
                               descriptors.value);

        auto* info = new SigfmImgInfo{std::move(keypoints.value),
                                      std::move(descriptors.value)};
        return info;
    }
    catch (...) {
        return nullptr;
    }
}

int sigfm_match_score(SigfmImgInfo* frame, SigfmImgInfo* enrolled)
{
    if (frame == nullptr || enrolled == nullptr || frame->descriptors.empty() ||
        enrolled->descriptors.empty()) {
        return 0;
    }

    try {
        SensitiveNestedVector<cv::DMatch> forward;
        SensitiveNestedVector<cv::DMatch> backward;
        SensitiveVector<int> candidate_positions;
        SensitiveVector<int> candidate_indices;
        SensitiveMat candidate_descriptors;
        SensitiveVector<match> matches;
        SensitiveVector<angle> angles;
        auto matcher = cv::BFMatcher::create();

        forward.value.reserve (frame->descriptors.rows);
        candidate_indices.value.reserve (sift_nfeatures);
        matches.value.reserve (max_correspondences);
        angles.value.reserve (max_correspondences *
                              (max_correspondences - 1) / 2);
        matcher->knnMatch(frame->descriptors, enrolled->descriptors,
                          forward.value, 2);
        candidate_positions.value.assign(enrolled->descriptors.rows, -1);
        for (const auto& candidates : forward.value) {
            if (candidates.size() < 2) {
                continue;
            }
            const cv::DMatch& nearest = candidates[0];
            if (nearest.distance < distance_match * candidates[1].distance &&
                candidate_positions.value[nearest.trainIdx] < 0) {
                candidate_positions.value[nearest.trainIdx] =
                    static_cast<int>(candidate_indices.value.size());
                candidate_indices.value.push_back(nearest.trainIdx);
            }
        }
        if (candidate_indices.value.size() < min_match) {
            return 0;
        }
        candidate_descriptors.value.create(
            static_cast<int>(candidate_indices.value.size()),
            enrolled->descriptors.cols, enrolled->descriptors.type());
        for (std::size_t index = 0; index < candidate_indices.value.size(); index++) {
            enrolled->descriptors.row(candidate_indices.value[index]).copyTo(
                candidate_descriptors.value.row(static_cast<int>(index)));
        }
        backward.value.reserve (candidate_indices.value.size());
        matcher->knnMatch(candidate_descriptors.value, frame->descriptors,
                          backward.value, 1);
        for (const auto& candidates : forward.value) {
            if (candidates.size() < 2) {
                continue;
            }
            const cv::DMatch& nearest = candidates[0];
            if (nearest.distance >= distance_match * candidates[1].distance) {
                continue;
            }
            const int position = candidate_positions.value[nearest.trainIdx];
            if (position < 0 || backward.value[position].empty() ||
                backward.value[position][0].trainIdx != nearest.queryIdx) {
                continue;
            }
            match correspondence{frame->keypoints.at(nearest.queryIdx).pt,
                                 enrolled->keypoints.at(nearest.trainIdx).pt};
            if (std::find(matches.value.begin(), matches.value.end(), correspondence) ==
                matches.value.end()) {
                matches.value.push_back(correspondence);
                if (matches.value.size() == max_correspondences) {
                    break;
                }
            }
        }
        if (matches.value.size() < min_match) {
            return 0;
        }

        for (std::size_t first = 0; first < matches.value.size(); first++) {
            for (std::size_t second = first + 1; second < matches.value.size(); second++) {
                const match& a = matches.value[first];
                const match& b = matches.value[second];
                const double x1 = a.p1.x - b.p1.x;
                const double y1 = a.p1.y - b.p1.y;
                const double x2 = a.p2.x - b.p2.x;
                const double y2 = a.p2.y - b.p2.y;
                const double length1 = std::hypot(x1, y1);
                const double length2 = std::hypot(x2, y2);

                if (length1 == 0.0 || length2 == 0.0 ||
                    1.0 - std::min(length1, length2) /
                              std::max(length1, length2) > length_match) {
                    continue;
                }
                const double product = length1 * length2;
                const double dot = std::clamp((x1 * x2 + y1 * y2) / product,
                                              -1.0, 1.0);
                const double cross = std::clamp((x1 * y2 - y1 * x2) / product,
                                                -1.0, 1.0);
                angles.value.emplace_back(pi / 2.0 + std::asin(dot),
                                          std::acos(cross), a, b);
            }
        }
        if (angles.value.size() < min_match) {
            return 0;
        }

        int count = 0;
        for (std::size_t first = 0; first < angles.value.size(); first++) {
            for (std::size_t second = first + 1; second < angles.value.size(); second++) {
                const angle& a = angles.value[first];
                const angle& b = angles.value[second];
                const double max_sine = std::max(a.sine, b.sine);
                const double max_cosine = std::max(a.cosine, b.cosine);

                if (max_sine == 0.0 || max_cosine == 0.0) {
                    continue;
                }
                if (1.0 - std::min(a.sine, b.sine) / max_sine <= angle_match &&
                    1.0 - std::min(a.cosine, b.cosine) / max_cosine <= angle_match) {
                    if (count == INT_MAX) {
                        return INT_MAX;
                    }
                    count++;
                }
            }
        }
        return count;
    }
    catch (...) {
        return -1;
    }
}

void sigfm_free_info(SigfmImgInfo* info)
{
    wipe_info(info);
    delete info;
}
