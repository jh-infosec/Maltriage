"""
Entropy, and the byte counting underneath it.

Split out of `extractors.py` when the secret engine needed the same maths and
could not import a module that imports it. Two callers rather than one is the
point at which a shared home is cheaper than an import cycle, and this is also
the first slice of the split `extractors.py` has needed since it passed three
thousand lines.

Nothing here knows what a sample is. It counts bytes and computes numbers.
"""

from __future__ import annotations
import math
from collections import Counter

BYTE_VALUES = 256


# byte counting

try:  # optional accelerator, not a hard requirement
    import numpy as _np

    def byte_counts(data: bytes) -> list[int]:
        """Histogram of the 256 byte values, as a fixed-length list."""
        if not data:
            return [0] * BYTE_VALUES
        return _np.bincount(
            _np.frombuffer(data, dtype=_np.uint8), minlength=BYTE_VALUES
        ).tolist()

    HAVE_NUMPY = True
except ImportError:
    def byte_counts(data: bytes) -> list[int]:
        """Histogram of the 256 byte values, as a fixed-length list."""
        counts = [0] * BYTE_VALUES
        for value, count in Counter(data).items():
            counts[value] = count
        return counts

    HAVE_NUMPY = False



def entropy_from_counts(counts, total: int) -> float:
    """Shannon entropy in bits per byte, from a byte histogram.

    Taking counts rather than bytes is what makes the streaming refactor
    possible: the histogram of a file is the sum of the histograms of its
    parts, so the whole-file figure needs nothing held in memory.
    """
    if total <= 0:
        return 0.0
    # The `+ 0.0` is not decoration. A region with all its mass in one bucket
    # negates to -0.0, which compares equal to zero and then serialises into
    # the report as "-0.0", so a flat section reads as though something odd
    # happened to it.
    return -sum((c / total) * math.log2(c / total) for c in counts if c) + 0.0


def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range 0.0 (uniform) to 8.0 (random)."""
    return entropy_from_counts(byte_counts(data), len(data))


def expected_random_entropy(n: int, alphabet: int = BYTE_VALUES) -> float:
    """What uniformly random data of length `n` actually scores.

    The plug-in entropy estimator is biased low on short samples: 375 random
    bytes cannot fill 256 buckets evenly, so they measure about 7.42 rather
    than 8.0. A fixed threshold of 7.5 is therefore unreachable at that size,
    which is exactly why v0.1.0 never flagged a small packed file.

    This is the Miller bias correction, log2(K) - (K-1)/(2n ln2), floored by
    log2(n) since n samples cannot express more than log2(n) bits. Measured
    against random data it predicts within 1.5% from 128 bytes upward.

    Scoring entropy as a ratio of this reference makes one threshold correct
    at every window size.

    `alphabet` is how many distinct symbols the source can emit. It defaults
    to every byte value, which is right for a slice of a file and wrong for a
    token: an API key drawn from base64 has 64 symbols and cannot reach eight
    bits per character however random it is. Passing the real alphabet is what
    lets one threshold be correct for a file window and for a forty-character
    credential.
    """
    if n <= 1 or alphabet <= 1:
        return 0.0
    corrected = math.log2(alphabet) - (alphabet - 1) / (2 * n * math.log(2))
    return max(0.0, min(math.log2(n), corrected))


def ratio(observed: float, n: int) -> float:
    reference = expected_random_entropy(n)
    return round(observed / reference, 4) if reference > 0 else 0.0
