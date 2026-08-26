def inspect(value):
    return getattr(value, "stat")()
