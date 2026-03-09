# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
    # Use UUID-based filename instead of user input to eliminate attack surface
    secure_filename = "#{SecureRandom.uuid}#{File.extname(file.original_filename).downcase}"
    
    # Validate file extension against whitelist
    validate_extension(file.original_filename)
    
    # Validate file size to prevent DoS attacks
    raise SecurityError, "File size exceeds maximum allowed" if file.size > MAX_FILE_SIZE
    
    # Verify content type matches extension
    verify_file_content(file)
    
    data_path = Rails.root.join("public", "data")
    full_file_name = data_path.join(secure_filename)
    
    # Verify the resolved path is within data_path using realpath for symlink protection
    unless safe_path?(full_file_name, data_path)
      raise SecurityError, "Invalid file path detected"
    end
    
    # Use block form to ensure file is properly closed
    File.open(full_file_name, "wb+") do |f|
      f.write file.read
    end
    
    # Scan file for malware after writing
    scan_file(full_file_name)
    
    # Store filename mapping in database for retrieval
    store_filename_mapping(secure_filename, file.original_filename)
    
    make_backup(secure_filename, data_path, full_file_name) if backup == "true"
  rescue SecurityError => e
    Rails.logger.warn("File upload security error: #{e.message}")
def self.make_backup(secure_filename, data_path, full_file_name)
    if File.exist?(full_file_name)
      backup_name = data_path.join("bak#{Time.zone.now.to_i}_#{secure_filename}")
      # Use FileUtils.cp instead of system command to prevent command injection
      FileUtils.cp(full_file_name, backup_name)
    end
  end

def self.validate_extension(filename)
    # Whitelist of allowed file extensions for security
    allowed_extensions = %w[.pdf .doc .docx .jpg .jpeg .png .txt .csv .xls .xlsx]
    
    ext = File.extname(filename).downcase
    unless allowed_extensions.include?(ext)
      raise SecurityError, "File type not allowed: #{ext}"
    end
    
    ext
def self.verify_file_content(file)
    # Validate actual file content, not just extension to prevent spoofing
    allowed_types = ['application/pdf', 'application/msword', 
                     'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                     'image/jpeg', 'image/png', 'text/plain', 'text/csv',
                     'application/vnd.ms-excel',
                     'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
    
    # Read file content to detect MIME type
    file_content = file.read
    file.rewind
    detected_type = Marcel::MimeType.for(file_content, name: file.original_filename)
    
    unless allowed_types.include?(detected_type)
      raise SecurityError, "File content type not allowed: #{detected_type}"
    end
def self.safe_path?(full_path, base_path)
    # Use realpath instead of expand_path for stronger symlink protection
    begin
      expanded_full = File.realpath(full_path.to_s)
    rescue
      # Path doesn't exist yet, use expand_path for validation
      expanded_full = File.expand_path(full_path.to_s)
    end
    
    expanded_base = File.realpath(base_path.to_s)
    
    # Ensure the full path starts with the base path to prevent directory traversal
    expanded_full.start_with?(expanded_base + File::SEPARATOR) ||
      expanded_full == expanded_base
def self.scan_file(file_path)
    # Integrate virus scanning for malware detection
    scan_command = "clamscan --no-summary #{file_path.to_s.shellescape}"
    system(scan_command)
    
    unless $?.exitstatus == 0
      # Delete file immediately if scan fails
      File.delete(file_path) if File.exist?(file_path)
      raise SecurityError, "File failed security scan"
    end
  rescue => e
    Rails.logger.error("Virus scan error: #{e.message}")
def self.store_filename_mapping(secure_filename, original_filename)
    # Store mapping between UUID and original filename for retrieval
    FileMapping.create!(
      secure_filename: secure_filename,
      original_filename: original_filename,
      uploaded_at: Time.zone.now
    )
  end

def self.MAX_FILE_SIZE
    10.megabytes
  end
