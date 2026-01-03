import deconvolute


def test_version_exists() -> None:
    assert hasattr(deconvolute, "__version__")
    assert isinstance(deconvolute.__version__, str)
    assert len(deconvolute.__version__) > 0
