from iocbot.collectors.abusech import _family_from_tags, _split_tags


def test_split_tags_strips_hash_and_whitespace():
    assert _split_tags("#ursnif #stenography #image") == ["ursnif", "stenography", "image"]
    assert _split_tags("smokeloader, zip") == ["smokeloader", "zip"]
    assert _split_tags(None) == []


def test_family_from_tags_rejects_junk():
    assert _family_from_tags(["image", "stego", "ursnif"]) == ""
    assert _family_from_tags(["jar", "malware"]) == ""
    assert _family_from_tags([".jar", "malware"]) == ""
    assert _family_from_tags(["#image"]) == ""


def test_family_from_tags_accepts_known_families():
    assert _family_from_tags(["smokeloader"]) == "smokeloader"
    assert _family_from_tags(["#emotet"]) == "emotet"
    assert _family_from_tags(["asyncrat"]) == "asyncrat"
