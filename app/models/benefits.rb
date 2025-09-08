# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  # Set maximum file size (10MB)
  MAX_FILE_SIZE = 10 * 1024 * 1024
  
  # Check file size to prevent DoS attacks
  raise "File too large" if file.size > MAX_FILE_SIZE
  
  # Perform virus scan on uploaded file
  scan_file(file)
  
  # Create secure temporary file for processing
  ext = File.extname(file.original_filename).downcase
  temp_file = Tempfile.new(['upload', ext])
  temp_file.binmode
  temp_file.write(file.read)
  temp_file.rewind
  
  # Verify content type, not just extension
  content_type = Marcel::MimeType.for(temp_file)
  allowed_types = ['application/pdf', 'image/jpeg', 'image/png', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
  unless allowed_types.include?(content_type)
    temp_file.close!
    Rails.logger.error("Invalid file type detected: #{content_type}")
    raise "Invalid file type"
  end
  
  # Sanitize the filename to remove path traversal components
  safe_filename = File.basename(file.original_filename).gsub(/[^0-9A-Za-z.\-]/, '_')
  
  # Use a whitelist approach for file extensions
  allowed_extensions = %w[.pdf .doc .docx .jpg .png]
  unless allowed_extensions.include?(ext)
    temp_file.close!
    Rails.logger.error("Invalid file extension: #{ext}")
    raise "Invalid file extension"
  end
  
  # Store files in a specific directory with a generated name
  data_path = Rails.root.join("public", "data")
  # Add a unique identifier to prevent overwriting
  safe_filename = "#{SecureRandom.uuid}_#{safe_filename}"
  full_file_name = File.join(data_path, safe_filename)
  
  # Ensure the final path is within the intended directory
  unless full_file_name.start_with?(data_path.to_s)
    temp_file.close!
    Rails.logger.error("Path traversal attempt detected: #{full_file_name}")
    raise "Invalid file path detected"
  end
  
  begin
    # Security logging for upload attempt
    Rails.logger.info("File upload attempt: #{safe_filename} by user #{current_user&.id || 'anonymous'}")
    
    # Write the file using a block to ensure proper closure
    File.open(full_file_name, "wb+") do |f|
      temp_file.rewind
      f.write temp_file.read
    end
    
    # Security logging for successful upload
    Rails.logger.info("File upload successful: #{safe_filename} stored at #{full_file_name}")
    
    make_backup(temp_file, data_path, full_file_name) if backup == "true"
    return safe_filename # Return the safe filename for reference
  
  rescue => e
    # Secure error handling to prevent information leakage
    Rails.logger.error("Upload error: #{e.message}")
    raise "File upload failed due to security constraints"
  ensure
    # Make sure to close and unlink the temp file
    temp_file.close!
  end
end

# Helper method for virus scanning
def self.scan_file(file)
  # Implementation for virus scanning using ClamAV
  temp_path = file.tempfile.path
  result = `clamscan #{temp_path}`
  if result.include?("FOUND")
    Rails.logger.error("Malicious file detected during upload: #{file.original_filename}")
    raise "Malicious file detected"
  end
rescue Errno::ENOENT
  Rails.logger.warn("ClamAV not available, skipping virus scan")
  # In production, you might want to fail closed:
  # raise "Virus scanning unavailable, rejecting upload for security"
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
