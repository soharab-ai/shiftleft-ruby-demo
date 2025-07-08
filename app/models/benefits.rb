# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  data_path = Rails.root.join("public", "data")
  
  # Define allowed MIME types for security
  ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain']
  
  # Validate file content type
  unless ALLOWED_MIME_TYPES.include?(file.content_type)
    raise "Invalid file type: only JPG, PNG, PDF and TXT files are allowed"
  end
  
  # Generate UUID-based filename with original extension instead of sanitizing user input
  extension = File.extname(file.original_filename)
  safe_filename = "#{SecureRandom.uuid}#{extension}"
  
  # Use secure path joining instead of string concatenation
  full_file_name = File.join(data_path.to_s, safe_filename)
  
  # Validate that the destination path is within the intended directory
  unless full_file_name.start_with?(data_path.to_s)
    raise "Invalid file path detected: potential directory traversal attempt"
  end
  
  # Secondary path canonicalization check to handle symbolic links
  begin
    unless File.realpath(File.dirname(full_file_name)).start_with?(File.realpath(data_path.to_s))
      raise "Path traversal detected after canonicalization"
    end
  rescue Errno::ENOENT
    # Handle case where directory doesn't exist yet
    FileUtils.mkdir_p(File.dirname(full_file_name))
    retry
  end
  
  # Create a wrapper method to constrain file operations (chroot-like environment)
  def write_file_safely(path, content)
    data_root = Rails.root.join("public", "data").to_s
    unless path.start_with?(data_root)
      raise "Security constraint: Cannot write outside data directory"
    end
    File.binwrite(path, content)
  end
  
  # Use the safe wrapper method instead of direct file operations
  write_file_safely(full_file_name, file.read)
  
  make_backup(file, data_path, full_file_name) if backup == "true"
  
  # Return the safe filename for reference
  safe_filename
end


  def self.make_backup(file, data_path, full_file_name)
    if File.exist?(full_file_name)
      silence_streams(STDERR) { system("cp #{full_file_name} #{data_path}/bak#{Time.zone.now.to_i}_#{file.original_filename}") }
    end
  end

  def self.silence_streams(*streams)
    on_hold = streams.collect { |stream| stream.dup }
    streams.each do |stream|
      stream.reopen(RUBY_PLATFORM =~ /mswin/ ? "NUL:" : "/dev/null")
      stream.sync = true
    end
    yield
  ensure
    streams.each_with_index do |stream, i|
      stream.reopen(on_hold[i])
    end
  end
end
