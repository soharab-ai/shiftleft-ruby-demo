# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
    # Whitelist-based directory selection for enhanced security
    data_path = Pathname.new(ALLOWED_DIRECTORIES.fetch('data'))
    
    # Extract and validate file extension against whitelist
    extension = File.extname(file.original_filename).downcase
    raise ArgumentError, "File type not allowed" unless ALLOWED_EXTENSIONS.include?(extension)
    
    # Generate deterministic filename using secure random UUID to eliminate user control
    safe_filename = "#{SecureRandom.uuid}_#{Time.now.to_i}#{extension}"
    
    # Construct safe path using join to prevent path traversal
    full_file_name = data_path.join(safe_filename).to_s
    
    # Strengthen path canonicalization check using realpath to resolve symbolic links
    begin
      resolved_path = Pathname.new(full_file_name).realpath(data_path.parent)
    rescue Errno::ENOENT
      # Path doesn't exist yet, so manually verify the parent directory is safe
      parent_dir = Pathname.new(File.dirname(full_file_name)).expand_path
      unless parent_dir.to_s.start_with?(data_path.to_s)
        raise SecurityError, "Path traversal attempt detected"
      end
      resolved_path = Pathname.new(full_file_name).expand_path
    end
    
    # Verify the resolved path is still within the intended directory
    unless resolved_path.to_s.start_with?(data_path.to_s)
      raise SecurityError, "Path traversal attempt detected"
    end
    
    # Use block form to ensure file is properly closed
    File.open(full_file_name, "wb+") do |f|
      f.write file.read
    end
    
    make_backup(file, data_path, full_file_name) if backup == "true"
  end

