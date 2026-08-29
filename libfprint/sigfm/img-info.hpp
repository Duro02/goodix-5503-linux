// SPDX-License-Identifier: LGPL-2.1-or-later
// SIGFM data structure, Copyright (C) 2022 SIGFM contributors.
#pragma once

#include <opencv2/core.hpp>
#include <vector>

struct SigfmImgInfo {
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
};