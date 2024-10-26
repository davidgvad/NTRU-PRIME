import numpy as np

def padding_encode(input_arr, block_size):
    """
    Pad the input array so its length is a multiple of the block size.
    """
    # Calculate the number of elements needed to reach the next multiple of block_size.
    n = block_size - len(input_arr) % block_size

    # If the array length is already a multiple of block_size, pad with block_size zeros.
    if n == block_size:
        return np.pad(input_arr, (0, n), 'constant')

    # Otherwise, pad the input array with n zeros and add a block of ones at the end.
    last_block = np.pad(np.ones(n), (block_size - n, 0), 'constant')
    return np.concatenate((np.pad(input_arr, (0, n), 'constant'), last_block))

def padding_decode(input_arr, block_size):
    """
    Remove padding from the array that was added by padding_encode.
    """
    # Get the last block to determine how much padding was added.
    last_block = input_arr[-block_size:]

    # Count the number of trailing zeros to determine the actual data's end.
    zeros_to_remove = len(np.trim_zeros(last_block))
    
    # Return the array without the padding.
    return input_arr[:-(block_size + zeros_to_remove)]
