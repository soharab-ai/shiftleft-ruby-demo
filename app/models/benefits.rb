# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  # Store files outside web root for better security
  data_path = Rails.root.join("storage", "uploads")
  
  # Create directory if it doesn't exist
  FileUtils.mkdir_p(data_path) unless File.directory?(data_path)
  
  # Content-type validation before processing the file
  allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
  unless allowed_types.include?(file.content_type)
    raise SecurityError, "File type not allowed"
  end
  
  # Generate secure random filename while preserving extension
  original_extension = File.extname(file.original_filename).gsub(/[^a-zA-Z0-9\.]/, '')
  safe_filename = SecureRandom.uuid + original_extension
  full_file_name = File.join(data_path, safe_filename)
  
  # Use path canonicalization to verify path security
  canonical_path = File.expand_path(full_file_name)
  canonical_data_path = File.expand_path(data_path.to_s)
  unless canonical_path.start_with?(canonical_data_path)
    raise SecurityError, "Invalid file path detected"
  end
  
  # Write the file with proper error handling
  File.open(full_file_name, "wb+") do |f|
    f.write file.read
  end
  
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
