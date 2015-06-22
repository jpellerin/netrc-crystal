$VERBOSE = true
require "minitest/autorun"

require "../src/netrc"

class TestParse < Minitest::Test
  def test_parse_empty
    pre, items = Netrc.parse([] of String)
    assert_equal("", pre)
    assert_equal([] of String, items)
  end

  def test_parse_comment
    pre, items = Netrc.parse(["# foo\n"])
    assert_equal("# foo\n", pre)
    assert_equal([] of String, items)
  end

  def test_parse_item
    t = ["machine", " ", "m", " ", "login", " ", "l", " ", "password", " ", "p", "\n"]
    pre, items = Netrc.parse(t)
    assert_equal("", pre)
    e = [["machine ", "m", " login ", "l", " password ", "p", "\n"]]
    assert_equal(e, items)
  end

  def test_parse_two_items
    t = ["machine", " ", "m", " ", "login", " ", "l", " ", "password", " ", "p", "\n"]
    t = t + t
    pre, items = Netrc.parse(t)
    assert_equal("", pre)
    e = [["machine ", "m", " login ", "l", " password ", "p", "\n"]]
    e = e + e
    assert_equal(e, items)
  end
end
