$VERBOSE = true
require "minitest/autorun"

require "../src/netrc"

class TestNetrc < Minitest::Test

  def test_parse_empty
    pre, items = Netrc.parse(Netrc.lex([] of String))
    assert_equal("", pre)
    assert_equal([] of String, items)
  end

  def test_parse_file
    pre, items = Netrc.parse(Netrc.lex(File.read_lines("data/sample.netrc")))
    assert_equal("# this is my netrc\n", pre)
    exp = [["machine ",
            "m",
            "\n  login ",
            "l",
            " # this is my username\n  password ",
            "p",
            "\n"]]
    assert_equal(exp, items)
  end

  def test_login_file
    pre, items = Netrc.parse(Netrc.lex(File.read_lines("data/login.netrc")))
    assert_equal("# this is my login netrc\n", pre)
    exp = [["machine ",
            "m",
            "\n  login ",
            "l",
            " # this is my username\n"]]
    assert_equal(exp, items)
  end

  def test_password_file
    pre, items = Netrc.parse(Netrc.lex(File.read_lines("data/password.netrc")))
    assert_equal("# this is my password netrc\n", pre)
    exp = [["machine ",
            "m",
            "\n  password ",
            "p",
            " # this is my password\n"]]
    assert_equal(exp, items)
  end

  def test_missing_file
    # pp "test missing file"
    n = Netrc.read("data/nonexistent.netrc")
    assert_equal(0, n.length)
  end

  def test_round_trip
    n = Netrc.read("data/sample.netrc")
    assert_equal(File.read("data/sample.netrc"), n.unparse)
  end

  def test_set
    n = Netrc.read("data/sample.netrc")
    n["m"] = "a", "b"
    exp = "# this is my netrc\n"+
          "machine m\n"+
          "  login a # this is my username\n"+
          "  password b\n"
    assert_equal(exp, n.unparse)
  end

  def test_set_get
    n = Netrc.read("data/sample.netrc")
    n["m"] = "a", "b"
    assert_equal(["a", "b"], n["m"].try{|v| v.to_a})
  end

  def test_add
    n = Netrc.read("data/sample.netrc")
    n.new_item_prefix = "# added\n"
    n["x"] = "a", "b"
    exp = "# this is my netrc\n"+
          "machine m\n"+
          "  login l # this is my username\n"+
          "  password p\n"+
          "# added\n"+
          "machine x\n"+
          "  login a\n"+
          "  password b\n"
    assert_equal(exp, n.unparse)
  end

  def test_add_newlineless
    n = Netrc.read("data/newlineless.netrc")
    n.new_item_prefix = "# added\n"
    n["x"] = "a", "b"
    exp = "# this is my netrc\n"+
          "machine m\n"+
          "  login l # this is my username\n"+
          "  password p\n"+
          "# added\n"+
          "machine x\n"+
          "  login a\n"+
          "  password b\n"
    assert_equal(exp, n.unparse)
  end

  def test_add_get
    n = Netrc.read("data/sample.netrc")
    n.new_item_prefix = "# added\n"
    n["x"] = "a", "b"
    assert_equal(["a", "b"], n["x"].try{ |v| v.to_a })
  end

  def test_get_missing
    n = Netrc.read("data/sample.netrc")
    assert_equal(nil, n["x"])
  end

  def test_save
    n = Netrc.read("data/sample.netrc")
    n.save
    assert_equal(File.read("data/sample.netrc"), n.unparse)
  end

  def test_save_create
    begin 
      File.delete("/tmp/created.netrc")
    rescue
      # nop
    end
    n = Netrc.read("/tmp/created.netrc")
    n.save
    # TODO(jhp) Fix when chmod/create mode supported
    # unless Netrc::WINDOWS
    # assert_equal(0600, File.stat("/tmp/created.netrc").mode & 0777)
    # end
    # pp "end test save create"
  end

  def test_encrypted_roundtrip
    if `gpg --list-keys 2> /dev/null` != ""
      begin 
        File.delete("/tmp/test.netrc.gpg")
      rescue
        # nop
      end
      n = Netrc.read("/tmp/test.netrc.gpg")
      n["m"] = "a", "b"
      n.save
      # TODO(jhp) Fix when chmod/create mode supported
      # assert_equal(0600, File.stat("/tmp/test.netrc.gpg").mode & 0777)
      netrc = Netrc.read("/tmp/test.netrc.gpg")["m"]
      assert netrc
      if netrc
        assert_equal("a", netrc.login)
        assert_equal("b", netrc.password)
      end
    end
  end

  def test_missing_environment
    home = ENV["HOME"]?
    if home
      ENV.delete("HOME")
    end
    assert_equal File.join(Dir.working_directory, ".netrc"), Netrc.default_path
  ensure
    if home
      ENV["HOME"] = home
    end
  end

  def test_read_entry
    entry = Netrc.read("data/sample.netrc")["m"]
    assert entry
    if entry
      assert_equal "l", entry.login
      assert_equal "p", entry.password

      # hash-style
      assert_equal "l", entry[:login]
      assert_equal "p", entry[:password]
    end
  end

  def test_write_entry
    n = Netrc.read("data/sample.netrc")
    entry = n["m"]
    assert entry
    if entry
      entry.login    = "new_login"
      entry.password = "new_password"
      n["m"] = entry
      assert_equal(["new_login", "new_password"], n["m"].try{ |v| v.to_a })
    end
  end

  def test_entry_splat
    e = Netrc::Entry.new("user", "pass")
    user, pass = e
    assert_equal("user", user)
    assert_equal("pass", pass)
  end

  def test_with_default
    netrc = Netrc.read("data/sample_with_default.netrc")
    assert_equal(["l", "p"], netrc["m"].try{|v| v.to_a})
    assert_equal(["default_login", "default_password"], netrc["unknown"].try{|v| v.to_a})
  end

  def test_multi_without_default
    netrc = Netrc.read("data/sample_multi.netrc")
    assert netrc
    if netrc
      assert_equal(["lm", "pm"], netrc["m"].try{|v| v.to_a})
      assert_equal(["ln", "pn"], netrc["n"].try{|v| v.to_a})
      assert_equal(nil, netrc["other"].try{|v| v.to_a})
    end
  end

  def test_multi_with_default
    netrc = Netrc.read("data/sample_multi_with_default.netrc")
    assert_equal(["lm", "pm"], netrc["m"].try{|v| v.to_a})
    assert_equal(["ln", "pn"], netrc["n"].try{|v| v.to_a})
    assert_equal(["ld", "pd"], netrc["other"].try{|v| v.to_a})
  end

  def test_default_only
    netrc = Netrc.read("data/default_only.netrc")
    assert_equal(["ld", "pd"], netrc["m"].try{|v| v.to_a})
    assert_equal(["ld", "pd"], netrc["other"].try{|v| v.to_a})
  end
end