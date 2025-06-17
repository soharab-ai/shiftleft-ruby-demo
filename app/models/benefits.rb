# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  data_path = Rails.root.join("public", "data")
  
  # Sanitize the filename by extracting just the base filename without path components
  safe_filename = File.basename(file.original_filename).gsub(/[^0-9A-Za-z.\-]/, '_')
  
  # Ensure we're only writing within the intended directory
  full_file_name = File.join(data_path, safe_filename)
  
  # Add file size validation to prevent DoS attacks
def self.make_backup(file, data_path, full_file_name, safe_filename)
  if File.exist?(full_file_name)
    # Use File.join for safe path construction and use the sanitized filename
    backup_filename = "bak#{Time.zone.now.to_i}_#{safe_filename}"
    backup_path = File.join(data_path, backup_filename)
    
    # Use FileUtils.cp instead of system call to avoid command injection
    FileUtils.cp(full_file_name, backup_path)
  end
end

  else
    raise "File size exceeds the maximum allowed limit"
  end
end


def self.make_backup(file, data_path, full_file_name)
  if File.exist?(full_file_name)
    # Extract just the safe base filename without path traversal potential
    safe_filename = File.basename(file.original_filename).gsub(/[^a-zA-Z0-9_\.-]/, '')
    
    # Only proceed if the filename passes validation checks
    if safe_filename.match?(/^[a-zA-Z0-9_\.-]+$/)
      # Create a safe backup name with timestamp
      backup_name = "#{data_path}/bak#{Time.zone.now.to_i}_#{safe_filename}"
      
      # Use FileUtils instead of system command to prevent command injection
      FileUtils.cp(full_file_name, backup_name)
    else
      Rails.logger.warn("Rejected potentially malicious filename: #{file.original_filename}")
    end
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
