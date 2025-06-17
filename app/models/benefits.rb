# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  data_path = Rails.root.join("public", "data")
  
  # Implement file type validation as suggested in mitigation notes
  allowed_types = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain']
  unless allowed_types.include?(file.content_type)
    raise SecurityError, "Invalid file type"
  end
  
  # Use SecureRandom for generated filenames instead of original filename
  extension = File.extname(file.original_filename).downcase
  random_name = SecureRandom.uuid + extension
  full_file_name = "#{data_path}/#{random_name}"
  
  # Store mapping of random name to original name in database if needed
  # Implementation would go here
  
  Rails.logger.info("Saving file with secure name: #{random_name}")
  
  f = File.open(full_file_name, "wb+")
  f.write file.read
  f.close
  
  make_backup(file, data_path, full_file_name, random_name) if backup == "true"
  
  return random_name # Return the generated name for reference
end

  # Ensure we're only writing within the intended directory
  full_file_name = File.join(data_path, safe_filename)
  
  # Add file size validation to prevent DoS attacks
def self.make_backup(file, data_path, full_file_name, safe_filename)
  if File.exist?(full_file_name)
    # Generate secure backup filename with timestamp
    backup_filename = "bak#{Time.zone.now.to_i}_#{safe_filename}"
    backup_path = File.join(data_path, backup_filename)
    
    # Add logging for security monitoring
    Rails.logger.info("Backup operation initiated for #{full_file_name}")
    
    silence_streams(STDERR) { FileUtils.cp(full_file_name, backup_path) }
    
    Rails.logger.info("Backup completed: #{backup_path}")
  end
end

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
