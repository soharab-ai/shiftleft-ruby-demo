# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
    data_path = Rails.root.join("public", "data")
    
    # Extract and validate file extension against whitelist
    original_extension = File.extname(file.original_filename).downcase
    allowed_extensions = ['.pdf', '.jpg', '.png', '.doc', '.docx']
    unless allowed_extensions.include?(original_extension)
      raise SecurityError, "File type not allowed"
    end
    
    # Generate cryptographically secure random filename to eliminate user control
    safe_filename = "#{SecureRandom.uuid}#{original_extension}"
    
    # Use File.join for safe path construction
    full_file_name = File.join(data_path, safe_filename)
    
    # Stricter canonicalization using realpath to resolve all symbolic links
    begin
      canonical_path = Pathname.new(full_file_name).realpath.to_s
      unless canonical_path.start_with?(data_path.realpath.to_s)
        raise SecurityError, "Directory traversal attempt detected"
      end
    rescue Errno::ENOENT
      # File doesn't exist yet (expected for new uploads), verify parent directory
      parent_dir = File.dirname(full_file_name)
      unless Pathname.new(parent_dir).realpath.to_s == data_path.realpath.to_s
        raise SecurityError, "Invalid upload directory"
      end
    end
    
    # Sanitize log entries to prevent log forging - remove newline characters
    sanitized_log_filename = file.original_filename.gsub(/[\r\n]/, '_')
    Rails.logger.info("File upload attempt: #{sanitized_log_filename}")
    
    # Verify actual file content type matches expected type for extension
    file.rewind
    detected_type = Marcel::MimeType.for(file)
    expected_types = {
      '.pdf' => 'application/pdf',
      '.jpg' => 'image/jpeg',
      '.png' => 'image/png',
      '.doc' => 'application/msword',
      '.docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }
    
    unless detected_type == expected_types[original_extension]
      raise SecurityError, "File content does not match declared type"
    end
    
    # Atomic file writing: write to temporary file first, then move atomically
    temp_file = File.join(data_path, "tmp_#{SecureRandom.hex(8)}")
    file.rewind
    File.open(temp_file, "wb+") do |f|
      f.write file.read
      f.chmod(0644)
    end
    
    # Atomic move to final location to prevent race conditions
    FileUtils.mv(temp_file, full_file_name, force: true)
    
    Rails.logger.info("File successfully saved: #{safe_filename}")
    
    make_backup(file, data_path, full_file_name) if backup == "true"
  end

