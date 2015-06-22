require "process"

class Netrc
  property new_item_prefix

  # TODO(jhp) add windows support
  WINDOWS = false
  CYGWIN  = false

  def self.default_path
    File.join(home_path, netrc_filename)
  end

  def self.home_path
    home = ENV["HOME"]

    if WINDOWS && !CYGWIN
      home ||= File.join(ENV["HOMEDRIVE"], ENV["HOMEPATH"]) if ENV["HOMEDRIVE"] && ENV["HOMEPATH"]
      home ||= ENV["USERPROFILE"]
      # XXX: old stuff; most likely unnecessary
      home = home.gsub("\\", "/") unless home.nil?
    end

    (home && File.exists?(home)) ? home : Dir.working_directory
  rescue ArgumentError
    return Dir.working_directory
  end

  def self.netrc_filename
    WINDOWS && !CYGWIN ? "_netrc" : ".netrc"
  end

  def self.config
    @@config ||= {} of Symbol => (Bool|String|Int32)
  end

  def self.configure
    yield(self.config) if block_given?
    self.config
  end

  def self.check_permissions(path)
    perm = File.stat(path).mode & 0777
    if perm != 0600 && !(WINDOWS) && !(Netrc.config[:allow_permissive_netrc_file]?)
      raise Exception.new(%x(Permission bits for "#{path}" should be 0600, but are )+perm.to_s(8))
    end
  end

  # Reads path and parses it as a .netrc file. If path doesn"t
  # exist, returns an empty object. Decrypt paths ending in .gpg.
  def self.read(path=default_path)
    check_permissions(path)
    data = if path =~ /\.gpg$/
      decrypted = `gpg --batch --quiet --decrypt #{path}`
      if $?.success?
        decrypted.split("\n")
      else
        raise Exception.new("Decrypting #{path} failed.")
      end
    else
      File.read_lines(path)
    end
    pp data
    if data
      new(path, parse(lex(data)))
    else
      raise Exception.new("Could not load #{path}")
    end
  rescue Errno
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
  def self.parse(ts) : {String, Array(Array(String))}
    cur, item = [] of String, [] of Array(String)

    pre = readto(ts){|t| t == "machine" || t == "default"}

    while ts.length > 0
      if ts[0] == "default"
        cur << take ts
        cur << ""
      else
        cur << take(ts) + readto(ts) {|t| ! skip?(t)}
        cur << take ts
      end

      if ts.includes?("login")
        cur << readto(ts) {|t| t == "login"} + take(ts) + readto(ts) {|t| ! skip?(t)}
        cur << take(ts)
      end

      if ts.includes?("password")
        cur << readto(ts) {|t| t == "password"} + take(ts) + readto(ts) {|t| ! skip?(t)}
        cur << take ts
      end

      cur << readto(ts) {|t| t == "machine" || t == "default"}

      item << cur
      cur = [] of String
    end

    {pre, item}
  end

  def self.take(ts)
    if ts.length < 1
      raise Exception.new("unexpected EOF")
    end
    ts.shift
  end

  def self.readto(ts)
    l = [] of String
    while ts.length > 0 && ! yield(ts[0])
      l << ts.shift
    end
    l.join
  end

  def initialize(@path, data)
    @new_item_prefix = ""
    @pre, @data = data

    if @data && @data.last && "default" == @data.last[0]
      @default = @data.pop
    else
      @default = nil
    end
  end

  def detect?
    i = 0
    while i < length
      e = @data[i]
      if yield e
        return e
      end
      i += 1
    end
    nil
  end

  def [](k)
    if item = detect? {|datum| datum[1] == k}
      Entry.new(item[3], item[5])
    else 
      # Have to alias to a local var to pass nil check
      df = @default
      if df 
        Entry.new(df[3], df[5])
      end
    end
  end

  def []=(k, info : Entry)
    l, p = info.login, info.password
    append(k, [l, p])
  end

  def []=(k, info : Array(String))
    append(k, info)
  end

  def append(k, info : Array(String?))
    l, p = info
    if l && p
      if item = detect? {|datum| datum[1] == k}    
        item[3], item[5] = l, p
      else
        @data << new_item(k, l, p)
      end
    else
      raise Exception.new("Invalid login/password array")
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
      status = Process.run("/bin/sh", args=["'gpg -a --batch --default-recipient-self -e -o #{@path}'"], input=StringIO.new(unparse))
      raise Exception.new("Encrypting #{@path} failed.") unless status.success?
    else
      File.open(@path, "w") {|file| file.print(unparse)}
    end
  end

  def unparse
    @pre + @data.map do |datum|
      datum = datum.join
      unless datum[-1..-1] == "\n"
        datum += "\n"
      else
        datum
      end
    end.join
  end

  struct Entry
    property login
    property password

    def initialize(@login, @password)
    end

    def initialize()
    end

    def [](k)
      to_a[k]
    end

    def [](k : Symbol)
      if k == :login
        @login
      elsif k == :password
        @password
      else
        raise MissingKey.new("Entry has no property #{k}")
      end
    end

    def to_a
      [@login, @password] of String?
    end
  end

end

class Netrc::Error < Exception
end
