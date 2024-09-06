import json

import pytest

from cosl.coordinated_workers.interface import DatabagModel, DataValidationError


class MyDataModel(DatabagModel):
    foo: int
    bar: str


def test_dump():
    # given a databag model subclass
    dm = MyDataModel(foo=1, bar="baz")

    # when you dump it
    out = dm.dump()

    # then you obtain a json-dict representation, flat
    assert out == {"foo": json.dumps(1), "bar": json.dumps("baz")}


def test_dump_to_mapping():
    # given a databag model subclass
    dm = MyDataModel(foo=1, bar="baz")

    # when you dump it to an arbitrary mapping
    databag = {"spurious": "data"}
    out = dm.dump(databag=databag)

    # then you obtain it back, populated
    assert databag is out
    assert databag == {"foo": json.dumps(1), "bar": json.dumps("baz")}


def test_dump_to_mapping_append():
    # given a databag model subclass
    dm = MyDataModel(foo=1, bar="baz")

    # when you dump it to an arbitrary mapping, without clearing it first
    databag = {"spurious": "data"}
    out = dm.dump(databag=databag, clear=False)

    # then you obtain it back, populated and with the existing data still there
    assert databag is out
    assert databag == {"foo": json.dumps(1), "bar": json.dumps("baz"), "spurious": "data"}


@pytest.mark.parametrize(
    "example",
    (
        {"foo": 1, "bar": "baz"},
        {"foo": 10, "bar": "lol"},
        {"foo": 11, "bar": "hola hola", "extra": "field"},
    ),
)
def test_load(example):
    # given a databag model subclass
    # when you instantiate it from an existing mapping
    dm = MyDataModel.load({key: json.dumps(value) for key, value in example.items()})
    # then you obtain a validated instance
    assert isinstance(dm, MyDataModel)
    assert dm.foo == example["foo"]


@pytest.mark.parametrize(
    "example",
    (
        {"foo": 1, "bar": 1},
        {"foo": [1, 2], "bar": "lol"},
        {"bar": "hola"},
    ),
)
def test_load_invalid_raises(example):
    # given a databag model subclass
    # when you instantiate it from an existing mapping with bad data
    # then you get an error
    with pytest.raises(DataValidationError):
        MyDataModel.load({key: json.dumps(value) for key, value in example.items()})
