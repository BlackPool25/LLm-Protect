"""
Entropy calculation and statistical analysis utilities.

Provides functions for calculating entropy and performing statistical tests
for steganography detection.
"""

import numpy as np
from typing import List, Tuple
from scipy import stats


def calculate_entropy(data: np.ndarray) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Input data array
        
    Returns:
        Entropy value (higher = more random)
    """
    # Flatten the data
    flat_data = data.flatten()
    
    # Get unique values and their counts
    unique, counts = np.unique(flat_data, return_counts=True)
    
    # Calculate probabilities
    probabilities = counts / len(flat_data)
    
    # Calculate entropy
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    return float(entropy)


def calculate_chi_square(observed: np.ndarray, expected: np.ndarray = None) -> Tuple[float, float]:
    """
    Perform chi-square test for randomness.
    
    Args:
        observed: Observed frequency distribution
        expected: Expected frequency distribution (uniform if None)
        
    Returns:
        Tuple of (chi_square_statistic, p_value)
    """
    flat_observed = observed.flatten()
    
    # Get frequency distribution
    unique, counts = np.unique(flat_observed, return_counts=True)
    
    if expected is None:
        # Assume uniform distribution
        expected_freq = np.full_like(counts, len(flat_observed) / len(unique), dtype=float)
    else:
        # Use provided expected distribution
        _, expected_freq = np.unique(expected.flatten(), return_counts=True)
        
    # Perform chi-square test
    chi2_stat, p_value = stats.chisquare(counts, expected_freq)
    
    return float(chi2_stat), float(p_value)


def calculate_lsb_entropy(image_array: np.ndarray) -> List[float]:
    """
    Calculate entropy of LSB planes for each channel.
    
    Args:
        image_array: Image as numpy array (H, W, C)
        
    Returns:
        List of entropy values for each channel
    """
    entropies = []
    
    if len(image_array.shape) == 2:
        # Grayscale image
        lsb_plane = image_array & 1
        entropies.append(calculate_entropy(lsb_plane))
    else:
        # Color image
        for channel in range(image_array.shape[2]):
            lsb_plane = image_array[:, :, channel] & 1
            entropies.append(calculate_entropy(lsb_plane))
    
    return entropies


def analyze_bit_plane_complexity(data: np.ndarray, bit_position: int = 0) -> float:
    """
    Analyze complexity of a specific bit plane.
    
    Args:
        data: Input data array
        bit_position: Which bit to analyze (0 = LSB)
        
    Returns:
        Complexity score (0-1, higher = more complex/suspicious)
    """
    # Extract bit plane
    bit_plane = (data >> bit_position) & 1
    
    # Calculate metrics
    entropy = calculate_entropy(bit_plane)
    
    # Calculate transition frequency (how often bit value changes)
    transitions = np.sum(np.abs(np.diff(bit_plane.flatten())))
    max_transitions = len(bit_plane.flatten()) - 1
    transition_rate = transitions / max_transitions if max_transitions > 0 else 0
    
    # Combine metrics
    # For LSB, high entropy + high transition rate = suspicious
    complexity = (entropy / 8.0) * 0.6 + transition_rate * 0.4
    
    return float(complexity)


def calculate_correlation_coefficient(array1: np.ndarray, array2: np.ndarray) -> float:
    """
    Calculate Pearson correlation coefficient between two arrays.
    
    Args:
        array1: First array
        array2: Second array
        
    Returns:
        Correlation coefficient (-1 to 1)
    """
    flat1 = array1.flatten()
    flat2 = array2.flatten()
    
    # Ensure same length
    min_len = min(len(flat1), len(flat2))
    flat1 = flat1[:min_len]
    flat2 = flat2[:min_len]
    
    correlation = np.corrcoef(flat1, flat2)[0, 1]
    
    return float(correlation) if not np.isnan(correlation) else 0.0


def kolmogorov_smirnov_test(data: np.ndarray) -> Tuple[float, float]:
    """
    Perform Kolmogorov-Smirnov test for uniformity.
    
    Args:
        data: Input data array
        
    Returns:
        Tuple of (KS statistic, p-value)
    """
    flat_data = data.flatten()
    
    # Normalize to [0, 1]
    normalized = (flat_data - flat_data.min()) / (flat_data.max() - flat_data.min() + 1e-10)
    
    # Test against uniform distribution
    ks_stat, p_value = stats.kstest(normalized, 'uniform')
    
    return float(ks_stat), float(p_value)
