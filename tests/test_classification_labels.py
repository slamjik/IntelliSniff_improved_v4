from traffic_analyzer.classification import resolve_label_name


def test_resolve_numeric_str_label():
    assert resolve_label_name(0) == "Normal Traffic"
    assert resolve_label_name("2") == "Port Scan / Recon"


def test_resolve_textual_labels():
    assert resolve_label_name("benign") == "Normal Traffic"
    assert resolve_label_name("DoS") == "DoS Attack"
    assert resolve_label_name("webattack") == "Web Application Attack"


def test_resolve_unknown_label():
    assert resolve_label_name("mystery") == "Class mystery"
    assert resolve_label_name(None) == "Unknown"
