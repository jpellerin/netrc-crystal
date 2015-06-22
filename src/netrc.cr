module Netrc
  property new_item_prefix

  # TODO(jhp) add windows support
  WINDOWS = false
  CYGWIN  = false

  def self.default_path
    File.join(home_path, netrc_filename)
  end

  def self.home_path
    home = Dir.respond_to?(:home) ? Dir.home : ENV["HOME"]

    if WINDOWS && !CYGWIN
      home ||= File.join(ENV["HOMEDRIVE"], ENV["HOMEPATH"]) if ENV["HOMEDRIVE"] && ENV["HOMEPATH"]
      home ||= ENV["USERPROFILE"]
      # XXX: old stuff; most likely unnecessary
      home = home.gsub("\\", "/") unless home.nil?
    end

    (home && File.readable?(home)) ? home : Dir.pwd
  rescue ArgumentError
    return Dir.pwd
  end

  def self.netrc_filename
    WINDOWS && !CYGWIN ? "_netrc" : ".netrc"
  end

  def self.config
    @config ||= {} of Symbol => (Bool|String|Int32)
  end

  def self.configure
    yield(self.config) if block_given?
    self.config
  end

  def self.check_permissions(path)
    perm = File.stat(path).mode & 0777
    if perm != 0600 && !(WINDOWS) && !(Netrc.config[:allow_permissive_netrc_file])
      raise Error, "Permission bits for "#{path}" should be 0600, but are "+perm.to_s(8)
    end
  end

  # Reads path and parses it as a .netrc file. If path doesn"t
  # exist, returns an empty object. Decrypt paths ending in .gpg.
  def self.read(path=default_path)
    check_permissions(path)
    data = if path =~ /\.gpg$/
      decrypted = `gpg --batch --quiet --decrypt #{path}`
      if $?.success?
        decrypted
      else
        raise Error.new("Decrypting #{path} failed.") unless $?.success?
      end
    else
      File.read(path)
    end
    new(path, parse(lex(data.lines.to_a)))
  rescue Errno::ENOENT
    new(path, parse(lex([] of String)))
  end

  def self.lex(lines)
    tokens = [] of String
    
    lines.each do |line|
      tok = nil
      comment = nil
      line.each_char_with_index do |ch, i|
        char = ch.to_s
        if comment
          comment = comment + char
        else
          # handle the "space before comment" case
          peek = line[i+1]?
          if peek == '#'
            if tok
              tokens << tok
            end
            tok = nil
            comment = char
          else
            case char
            when "#"
              if tok
                tokens << tok
              end
              tok = nil
              comment = char
            when /\s/
              if tok && tok =~ /\s/
                tok = tok + char
              else
                if tok
                  tokens << tok
                end
                tok = char
              end
            else
              if tok && tok =~ /\S/
                tok = tok + char
              else
                if tok
                  tokens << tok
                end
                tok = char
              end
            end
          end
        end
        if i == line.length() -1
          if tok
            tokens << tok
          elsif comment
            tokens << comment
          end
        end
      end
    end
    tokens
  end

  def self.skip?(s)
    s =~ /^\s/
  end

  # Returns two values, a header and a list of items.
  # Each item is a tuple, containing some or all of:
  # - machine keyword (including trailing whitespace+comments)
  # - machine name
  # - login keyword (including surrounding whitespace+comments)
  # - login
  # - password keyword (including surrounding whitespace+comments)
  # - password
  # - trailing chars
  # This lets us change individual fields, then write out the file
  # with all its original formatting.
  def self.parse(ts)
    cur, item = [] of String, [] of String

    pre = readto{|t| t == "machine" || t == "default"}

    while ts.length > 0
      if ts[0] == "default"
        cur << take ts
        cur << ""
      else
        cur << take(ts) + readto ts {|t| ! skip?(t)}
        cur << take ts
      end

      if ts.include?("login")
        cur << readto ts {|t| t == "login"} + take(ts) + readto ts {|t| ! skip?(t)}
        cur << take(ts)
      end

      if ts.include?("password")
        cur << readto ts {|t| t == "password"} + take(ts) + readto ts {|t| ! skip?(t)}
        cur << take ts
      end

      cur << readto ts {|t| t == "machine" || t == "default"}

      item << cur
      cur = [] of String
    end

    [pre, item]
  end

  def take(ts)
    if ts.length < 1
      raise Error, "unexpected EOF"
    end
    ts.shift
  end

  def readto(ts)
    l = [] of String
    while ts.length > 0 && ! yield(ts[0])
      l << ts.shift
    end
    l.join
  end

  def initialize(path, data)
    @new_item_prefix = ""
    @path = path
    @pre, @data = data

    if @data && @data.last && :default == @data.last[0]
      @default = @data.pop
    else
      @default = nil
    end
  end

  def [](k)
    if item = @data.detect {|datum| datum[1] == k}
      Entry.new(item[3], item[5])
    elsif @default
      Entry.new(@default[3], @default[5])
    end
  end

  def []=(k, info)
    if item = @data.detect {|datum| datum[1] == k}
      item[3], item[5] = info
    else
      @data << new_item(k, info[0], info[1])
    end
  end

  def length
    @data.length
  end

  def delete(key)
    @data.delete_if{ |value| value == key }
  end

  def each(&block)
    @data.each(&block)
  end

  def new_item(m, l, p)
    [new_item_prefix+"machine ", m, "\n  login ", l, "\n  password ", p, "\n"]
  end

  def save
    if @path =~ /\.gpg$/
      e = IO.popen("gpg -a --batch --default-recipient-self -e", "r+") do |gpg|
        gpg.puts(unparse)
        gpg.close_write
        gpg.read
      end
      raise Error.new("Encrypting #{@path} failed.") unless $?.success?
      File.open(@path, "w", 0600) {|file| file.print(e)}
    else
      File.open(@path, "w", 0600) {|file| file.print(unparse)}
    end
  end

  def unparse
    @pre + @data.map do |datum|
      datum = datum.join
      unless datum[-1..-1] == "\n"
        datum << "\n"
      else
        datum
      end
    end.join
  end

  Entry = Struct.new(:login, :password)

end

class Netrc::Error < Exception
end
