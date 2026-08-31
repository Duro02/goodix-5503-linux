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
#include <cstdio>

#include <algorithm>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
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
constexpr unsigned char template_magic[] = { 'G', '5', '5', 'S' };
constexpr std::uint16_t template_version = 1;
constexpr std::size_t max_persisted_keypoints = 256;
constexpr std::size_t descriptor_columns = 128;
constexpr std::size_t persisted_keypoint_size = 28;
constexpr std::size_t persisted_header_size = 20;
constexpr std::size_t max_template_size = 1024 * 1024;
constexpr float max_persisted_coordinate = 4096.0f;

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
    cv::Point2d p1;
    cv::Point2d p2;

    match(cv::Point2f ip1, cv::Point2f ip2) : p1{ip1}, p2{ip2} {}
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

void append_u16(SensitiveVector<unsigned char>& output, std::uint16_t value)
{
    output.value.push_back(static_cast<unsigned char>(value));
    output.value.push_back(static_cast<unsigned char>(value >> 8));
}

void append_u32(SensitiveVector<unsigned char>& output, std::uint32_t value)
{
    for (unsigned shift = 0; shift < 32; shift += 8) {
        output.value.push_back(static_cast<unsigned char>(value >> shift));
    }
}

void append_float(SensitiveVector<unsigned char>& output, float value)
{
    std::uint32_t bits;
    static_assert(sizeof bits == sizeof value);
    std::memcpy(&bits, &value, sizeof bits);
    append_u32(output, bits);
}

bool read_u16(const unsigned char*& cursor, const unsigned char* end,
              std::uint16_t& value)
{
    if (static_cast<std::size_t>(end - cursor) < 2) {
        return false;
    }
    value = static_cast<std::uint16_t>(cursor[0]) |
            static_cast<std::uint16_t>(cursor[1]) << 8;
    cursor += 2;
    return true;
}

bool read_u32(const unsigned char*& cursor, const unsigned char* end,
              std::uint32_t& value)
{
    if (static_cast<std::size_t>(end - cursor) < 4) {
        return false;
    }
    value = static_cast<std::uint32_t>(cursor[0]) |
            static_cast<std::uint32_t>(cursor[1]) << 8 |
            static_cast<std::uint32_t>(cursor[2]) << 16 |
            static_cast<std::uint32_t>(cursor[3]) << 24;
    cursor += 4;
    return true;
}

bool read_float(const unsigned char*& cursor, const unsigned char* end,
                float& value)
{
    std::uint32_t bits;
    if (!read_u32(cursor, end, bits)) {
        return false;
    }
    std::memcpy(&value, &bits, sizeof value);
    return true;
}

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

SigfmImgInfo* sigfm_copy_info(const SigfmImgInfo* info)
{
    SigfmImgInfo* copy = nullptr;
    if (info == nullptr) {
        return nullptr;
    }
    try {
        copy = new SigfmImgInfo;
        copy->keypoints = info->keypoints;
        copy->descriptors = info->descriptors.clone();
        return copy;
    }
    catch (...) {
        wipe_info(copy);
        delete copy;
        return nullptr;
    }
}

unsigned char* sigfm_serialize(const SigfmImgInfo* info, std::size_t* length)
{
    if (length != nullptr) {
        *length = 0;
    }
    if (info == nullptr || length == nullptr || info->keypoints.empty() ||
        info->keypoints.size() > max_persisted_keypoints ||
        info->descriptors.type() != CV_32F ||
        info->descriptors.cols != static_cast<int>(descriptor_columns) ||
        info->descriptors.rows != static_cast<int>(info->keypoints.size())) {
        return nullptr;
    }

    try {
        const std::size_t descriptor_bytes =
            info->keypoints.size() * descriptor_columns * sizeof(float);
        const std::size_t total = persisted_header_size +
                                  info->keypoints.size() * persisted_keypoint_size +
                                  descriptor_bytes;
        if (total > max_template_size || total > UINT32_MAX) {
            return nullptr;
        }
        SensitiveVector<unsigned char> output;
        output.value.reserve(total);
        output.value.insert(output.value.end(), std::begin(template_magic),
                            std::end(template_magic));
        append_u16(output, template_version);
        append_u16(output, 0);
        append_u32(output, static_cast<std::uint32_t>(info->keypoints.size()));
        append_u16(output, static_cast<std::uint16_t>(descriptor_columns));
        append_u16(output, 1);
        append_u32(output, static_cast<std::uint32_t>(descriptor_bytes));
        for (const auto& point : info->keypoints) {
            if (!std::isfinite(point.pt.x) || !std::isfinite(point.pt.y) ||
                point.pt.x < 0.0f || point.pt.x > max_persisted_coordinate ||
                point.pt.y < 0.0f || point.pt.y > max_persisted_coordinate ||
                !std::isfinite(point.size) || point.size <= 0.0f ||
                !std::isfinite(point.angle) || !std::isfinite(point.response)) {
                return nullptr;
            }
            append_float(output, point.pt.x);
            append_float(output, point.pt.y);
            append_float(output, point.size);
            append_float(output, point.angle);
            append_float(output, point.response);
            append_u32(output, static_cast<std::uint32_t>(point.octave));
            append_u32(output, static_cast<std::uint32_t>(point.class_id));
        }
        for (int row = 0; row < info->descriptors.rows; row++) {
            for (int column = 0; column < info->descriptors.cols; column++) {
                const float descriptor = info->descriptors.at<float>(row, column);
                if (!std::isfinite(descriptor)) {
                    return nullptr;
                }
                append_float(output, descriptor);
            }
        }
        if (output.value.size() != total) {
            return nullptr;
        }
        auto* serialized = static_cast<unsigned char*>(std::malloc(total));
        if (serialized == nullptr) {
            return nullptr;
        }
        std::memcpy(serialized, output.value.data(), total);
        *length = total;
        return serialized;
    }
    catch (...) {
        return nullptr;
    }
}

SigfmImgInfo* sigfm_deserialize(const unsigned char* data, std::size_t length)
{
    SigfmImgInfo* info = nullptr;
    if (data == nullptr || length < persisted_header_size ||
        length > max_template_size ||
        std::memcmp(data, template_magic, sizeof template_magic) != 0) {
        return nullptr;
    }

    try {
        const unsigned char* cursor = data + sizeof template_magic;
        const unsigned char* end = data + length;
        std::uint16_t version, reserved, columns, type;
        std::uint32_t count, descriptor_bytes;
        if (!read_u16(cursor, end, version) ||
            !read_u16(cursor, end, reserved) ||
            !read_u32(cursor, end, count) ||
            !read_u16(cursor, end, columns) ||
            !read_u16(cursor, end, type) ||
            !read_u32(cursor, end, descriptor_bytes) ||
            version != template_version || reserved != 0 || count == 0 ||
            count > max_persisted_keypoints || columns != descriptor_columns ||
            type != 1 ||
            descriptor_bytes != count * descriptor_columns * sizeof(float)) {
            return nullptr;
        }
        const std::size_t expected = persisted_header_size +
                                     count * persisted_keypoint_size +
                                     descriptor_bytes;
        if (expected != length) {
            return nullptr;
        }

        info = new SigfmImgInfo;
        info->keypoints.reserve(count);
        for (std::uint32_t index = 0; index < count; index++) {
            cv::KeyPoint point;
            std::uint32_t octave, class_id;
            if (!read_float(cursor, end, point.pt.x) ||
                !read_float(cursor, end, point.pt.y) ||
                !read_float(cursor, end, point.size) ||
                !read_float(cursor, end, point.angle) ||
                !read_float(cursor, end, point.response) ||
                !read_u32(cursor, end, octave) ||
                !read_u32(cursor, end, class_id) ||
                !std::isfinite(point.pt.x) || !std::isfinite(point.pt.y) ||
                point.pt.x < 0.0f || point.pt.x > max_persisted_coordinate ||
                point.pt.y < 0.0f || point.pt.y > max_persisted_coordinate ||
                !std::isfinite(point.size) || point.size <= 0.0f ||
                !std::isfinite(point.angle) ||
                !std::isfinite(point.response)) {
                wipe_info(info);
                delete info;
                return nullptr;
            }
            point.octave = static_cast<std::int32_t>(octave);
            point.class_id = static_cast<std::int32_t>(class_id);
            info->keypoints.push_back(point);
        }
        info->descriptors.create(static_cast<int>(count),
                                 static_cast<int>(descriptor_columns), CV_32F);
        for (std::uint32_t row = 0; row < count; row++) {
            for (std::size_t column = 0; column < descriptor_columns; column++) {
                float value;
                if (!read_float(cursor, end, value) || !std::isfinite(value)) {
                    wipe_info(info);
                    delete info;
                    return nullptr;
                }
                info->descriptors.at<float>(static_cast<int>(row),
                                            static_cast<int>(column)) = value;
            }
        }
        if (cursor != end) {
            wipe_info(info);
            delete info;
            return nullptr;
        }
        return info;
    }
    catch (...) {
        wipe_info(info);
        delete info;
        return nullptr;
    }
}

void sigfm_free_serialized(unsigned char* data, std::size_t length)
{
    if (data != nullptr) {
        secure_wipe(data, length);
        std::free(data);
    }
}

int sigfm_equal(const SigfmImgInfo* left, const SigfmImgInfo* right)
{
    if (left == right) {
        return 1;
    }
    if (left == nullptr || right == nullptr ||
        left->keypoints.size() != right->keypoints.size() ||
        left->descriptors.type() != right->descriptors.type() ||
        left->descriptors.rows != right->descriptors.rows ||
        left->descriptors.cols != right->descriptors.cols) {
        return 0;
    }
    for (std::size_t index = 0; index < left->keypoints.size(); index++) {
        const auto& a = left->keypoints[index];
        const auto& b = right->keypoints[index];
        if (a.pt != b.pt || a.size != b.size || a.angle != b.angle ||
            a.response != b.response || a.octave != b.octave ||
            a.class_id != b.class_id) {
            return 0;
        }
    }
    for (int row = 0; row < left->descriptors.rows; row++) {
        if (std::memcmp(left->descriptors.ptr(row), right->descriptors.ptr(row),
                        static_cast<std::size_t>(left->descriptors.cols) *
                            left->descriptors.elemSize()) != 0) {
            return 0;
        }
    }
    return 1;
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
        auto sift = cv::SIFT::create(sift_nfeatures,
                                     sift_octave_layers,
                                     sift_contrast_threshold,
                                     sift_edge_threshold,
                                     sift_sigma);
        /* The sensor is fixed-orientation and the difference texture is
         * sparse: SIFT's dominant-orientation assignment is unstable between
         * captures on this canvas and can flip every descriptor alignment
         * (observed as all-or-nothing match scores). This reader never sees
         * rotated input, so force upright descriptors instead. */
        sift->detect (enhanced.value, keypoints.value, roi);
        for (auto& keypoint : keypoints.value)
            keypoint.angle = 0.0f;
        sift->compute (enhanced.value, keypoints.value, descriptors.value);

        const std::size_t retained =
            std::min<std::size_t> (keypoints.value.size (), sift_nfeatures);
        SensitiveVector<cv::KeyPoint> bounded_keypoints;
        SensitiveMat bounded_descriptors;
        bounded_keypoints.value.reserve (retained);
        bounded_keypoints.value.insert (bounded_keypoints.value.end (),
                                        keypoints.value.begin (),
                                        keypoints.value.begin () + retained);
        if (retained > 0)
          bounded_descriptors.value =
            descriptors.value.rowRange (0, static_cast<int> (retained)).clone ();
        auto* info = new SigfmImgInfo{std::move(bounded_keypoints.value),
                                      std::move(bounded_descriptors.value)};
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
        fprintf (stderr, "SIGFM score=0 (empty descriptors)\n");
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
            fprintf (stderr, "SIGFM score=0 (insufficient raw matches)\n");
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
            fprintf (stderr, "SIGFM score=0 (insufficient mutual matches)\n");
            return 0;
        }

        for (std::size_t first = 0; first < matches.value.size(); first++) {
            for (std::size_t second = first + 1; second < matches.value.size(); second++) {
                const match& a = matches.value[first];
                const match& b = matches.value[second];
                const double x1 = static_cast<double>(a.p1.x) -
                                  static_cast<double>(b.p1.x);
                const double y1 = static_cast<double>(a.p1.y) -
                                  static_cast<double>(b.p1.y);
                const double x2 = static_cast<double>(a.p2.x) -
                                  static_cast<double>(b.p2.x);
                const double y2 = static_cast<double>(a.p2.y) -
                                  static_cast<double>(b.p2.y);
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
            fprintf (stderr, "SIGFM score=0 (insufficient geometric matches)\n");
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
                        fprintf (stderr, "SIGFM score=INT_MAX\n");
                        return INT_MAX;
                    }
                    count++;
                }
            }
        }
        fprintf (stderr, "SIGFM score=%d (threshold driver-side)\n", count);
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
