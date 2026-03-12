# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.sanitize_filename(filename)
  # Remove path components and keep only the basename - prevents directory traversal
  basename = File.basename(filename)
  
  # Remove any remaining directory traversal attempts and special characters
  sanitized = basename.gsub(/[^0-9A-Za-z.\-_]/, '_')
  
  # Prevent hidden files and ensure reasonable length
  sanitized = sanitized.gsub(/^\.+/, '_')
  sanitized = sanitized[0..255]
  
  # Implement whitelist-based file extension validation - prevents executable uploads
  ALLOWED_EXTENSIONS = %w[.pdf .jpg .jpeg .png .doc .docx .txt].freeze
  
  extension = File.extname(sanitized).downcase
  unless ALLOWED_EXTENSIONS.include?(extension)
    raise SecurityError, "File type not permitted"
  end
  
  sanitized
end

  
  # Validate file size before reading
  if file.size > 10.megabytes
    raise SecurityError, "File size exceeds maximum limit"
  end
  
  # Use block form to ensure file is properly closed
  File.open(full_file_name, "wb") do |f|
    f.write file.read
  end
  
  make_backup(safe_filename, data_path, full_file_name) if backup == "true"
end


def self.make_backup(filename, data_path, full_file_name)
  if File.exist?(full_file_name)
    backup_filename = "bak#{Time.zone.now.to_i}_#{filename}"
    backup_path = data_path.join(backup_filename).to_s
    
    # Use FileUtils instead of system command to prevent command injection
    FileUtils.cp(full_file_name, backup_path)
  end
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
