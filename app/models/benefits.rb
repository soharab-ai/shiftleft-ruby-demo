# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
    # Validate filename before processing to prevent command injection
    unless valid_filename?(file.original_filename)
      raise ArgumentError, "Invalid filename provided"
    end
    
    # File size validation to prevent denial-of-service through disk space exhaustion
    MAX_FILE_SIZE = 10.megabytes
    if file.size > MAX_FILE_SIZE
      raise ArgumentError, "File size exceeds maximum allowed size of #{MAX_FILE_SIZE} bytes"
    end
    
    data_path = Rails.root.join("public", "data")
    # Sanitize filename to remove dangerous characters
    sanitized_name = sanitize_filename(file.original_filename)
    
    # Use File.expand_path to resolve canonical path and prevent path traversal
    full_file_name = File.expand_path(sanitized_name, data_path)
    # Validation to ensure the resolved path is still within data_path
    unless full_file_name.start_with?(data_path.to_s)
      raise ArgumentError, "Path traversal attempt detected"
    end
    
    # Generate temporary filename for atomic file operations
    temp_file_name = "#{full_file_name}.tmp.#{SecureRandom.hex(8)}"
    
    begin
      # Use block form to ensure file is properly closed, write to temporary file first
def self.make_backup(file, data_path, full_file_name)
    if File.exist?(full_file_name)
      # Sanitize filename to prevent command injection
      backup_filename = "bak#{Time.zone.now.to_i}_#{sanitize_filename(file.original_filename)}"
      backup_path = File.join(data_path, backup_filename)
      
      # Use Ruby's FileUtils instead of shell commands to prevent command injection
      FileUtils.cp(full_file_name, backup_path)
      
      # Set restrictive permissions on backup file to prevent unauthorized access
      FileUtils.chmod(0600, backup_path)
    end
def self.sanitize_filename(filename)
    # Handle encoding issues with Unicode and encoded characters
    sanitized = filename.encode('UTF-8', invalid: :replace, undef: :replace, replace: '_')
    
    # Remove null bytes explicitly to prevent bypass techniques
    sanitized = sanitized.delete("\x00")
    
    # Remove path traversal and dangerous characters to prevent command injection
    sanitized = File.basename(sanitized)
    # Replace all non-alphanumeric characters except dots, hyphens, and underscores
    sanitized = sanitized.gsub(/[^\w\.\-]/, '_')
def self.valid_filename?(filename)
    # Only allow alphanumeric, dots, hyphens, underscores to prevent command injection
    # Also prevent path traversal with double dots
    return false unless filename.match?(/\A[\w\.\-]+\z/) && !filename.include?('..')
    
    # File extension whitelist validation to prevent dangerous file types
    ALLOWED_EXTENSIONS = %w[.csv .txt .pdf .xlsx .doc .docx .xls .png .jpg .jpeg]
    file_extension = File.extname(filename).downcase
    
    # Return false if extension is not in whitelist (allow files without extension)
    return true if file_extension.empty?
    ALLOWED_EXTENSIONS.include?(file_extension)
  end
