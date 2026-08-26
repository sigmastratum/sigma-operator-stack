from pathlib import Path, PurePosixPath

def render(value: str) -> tuple[str, tuple[str, ...], str]:
    path = Path(value)
    pure = PurePosixPath(value)
    return path.as_posix(), pure.parts, pure.name
