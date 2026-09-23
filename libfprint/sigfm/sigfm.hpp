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
//

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef unsigned char SigfmPix;
/**
 * @brief Contains information used by the sigfm algorithm for matching
 * @details Get one from sigfm_extract() and make sure to clean it up with sigfm_free_info()
 * @struct SigfmImgInfo
 */
typedef struct SigfmImgInfo SigfmImgInfo;

/* Enrollment work is bounded separately from the persisted gallery. */
#define SIGFM_ENROLL_POOL_SAMPLES 40
#define SIGFM_ENROLL_TARGET_SAMPLES 24
#define SIGFM_ENROLL_BATCH_SAMPLES 10
#define SIGFM_ENROLL_BATCH_KEEP 6
#define SIGFM_ENROLL_CHECK_SAMPLES 8
#define SIGFM_ENROLL_CHECK_REQUIRED 6
#define SIGFM_ENROLL_TOTAL_STAGES (SIGFM_ENROLL_POOL_SAMPLES + SIGFM_ENROLL_CHECK_SAMPLES)

/** Select 24 indices from 40 newly collected samples. Six references survive
 * from each consecutive ten-sample guidance batch. Only training samples
 * enter selection; self-matches do not count as coverage. The subsequent
 * eight checks must remain held out.
 * Returns 0 on success or -1 on invalid input/matching error. */
int sigfm_select_enrollment(SigfmImgInfo *const *samples, size_t count,
                            int identity_threshold, unsigned *indices,
                            size_t capacity);

/**
 * @brief Extracts information from an image for later use sigfm_match_score
 *
 * @param pix Pixels of the image must be width * height in length
 * @param width Width of the image
 * @param height Height of the image
 * @return SigfmImgInfo* Info that can be used with the API
 */
SigfmImgInfo* sigfm_extract(const SigfmPix* pix, int width, int height);

/**
 * @brief Destroy an SigfmImgInfo
 * @warning Call this instead of free() or you will get UB!
 * @param info SigfmImgInfo to destroy
 */
void sigfm_free_info(SigfmImgInfo* info);

/**
 * @brief Score how closely a frame matches another
 *
 * @param frame Print to be checked
 * @param enrolled Canonical print to verify against
 * @return int Score of how closely they match, values <0 indicate error, 0 means always reject
 */
int sigfm_match_score(SigfmImgInfo* frame, SigfmImgInfo* enrolled);

/** Enrollment-only redundancy check; never use this as an identity decision.
 * Returns 1 only for near-identical, extensively shared feature coverage,
 * 0 when another view may add information, and -1 on error.
 */
int sigfm_is_redundant(SigfmImgInfo* frame, SigfmImgInfo* enrolled,
                       int identity_threshold);

/**
 * @brief Keypoints for an image. Low keypoints generally means the image is
 * low quality for matching
 *
 * @param info
 * @return int
 */

int sigfm_keypoints_count(SigfmImgInfo* info);

/** Deep-copy feature ownership. */
SigfmImgInfo* sigfm_copy_info(const SigfmImgInfo* info);

/** Canonical, versioned, fixed-endian feature persistence. */
unsigned char* sigfm_serialize(const SigfmImgInfo* info, size_t* length);
SigfmImgInfo* sigfm_deserialize(const unsigned char* data, size_t length);
void sigfm_free_serialized(unsigned char* data, size_t length);

/** Compare canonical feature contents. */
int sigfm_equal(const SigfmImgInfo* left, const SigfmImgInfo* right);

#ifdef __cplusplus
}
#endif
