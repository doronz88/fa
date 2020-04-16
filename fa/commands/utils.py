def read_memory(segments, ea, size):
    for segment_ea, data in segments.items():
        if (ea <= segment_ea + len(data)) and (ea >= segment_ea):
            offset = ea - segment_ea
            return data[offset:offset+size]
