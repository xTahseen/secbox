def fmt_size(num_bytes):
    """Convert a byte count into a short human-readable string (e.g. '158.14 KB')."""
    if num_bytes is None:
        return "Unknown"
    try:
        size = float(num_bytes)
    except (TypeError, ValueError):
        return "Unknown"

    if size < 1024:
        return f"{int(size)} B"

    units = ["KB", "MB", "GB", "TB"]
    unit_index = -1
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.2f} {units[unit_index]}"
