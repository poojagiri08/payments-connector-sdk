def test_import_package():
    import payments_sdk
    assert payments_sdk.__version__ == "0.1.0"