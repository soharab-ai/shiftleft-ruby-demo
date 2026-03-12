# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  # FIX: Validate file size to prevent DoS attacks (max 10MB)
  max_size = 10.megabytes
  raise ArgumentError, "File too large" if file.size > max_size
  
  data_path = Rails.root.join("public", "data")
  # FIX: Sanitize filename with stricter validation including extension whitelisting
  sanitized_filename = sanitize_filename(file.original_filename)
  
  # FIX: Generate unique filename using UUID to prevent race conditions and filename collisions
  unique_filename = "#{SecureRandom.uuid}_#{sanitized_filename}"
def self.make_backup(sanitized_filename, data_path, full_file_name)
  return unless File.exist?(full_file_name)
  
  backup_filename = "#{data_path}/bak#{Time.zone.now.to_i}_#{sanitized_filename}"
  
  begin
    # FIX: Use FileUtils.cp instead of system command to prevent command injection
    silence_streams(STDERR) { FileUtils.cp(full_file_name, backup_filename) }
def self.sanitize_filename(filename)
  # FIX: Extract extension and basename separately for stricter validation
  base = File.basename(filename, ".*")
  ext = File.extname(filename)
  
  # FIX: Whitelist allowed extensions to prevent extension-based attacks
  allowed_extensions = ['.pdf', '.csv', '.txt', '.xlsx', '.docx']
  ext = allowed_extensions.include?(ext.downcase) ? ext.downcase : ''
  
  # FIX: Sanitize basename with alphanumeric and underscores only, limit length to 100 chars
  base = base.gsub(/[^\w]/, '_').gsub(/_+/, '_').slice(0, 100)
  
  # FIX: Prevent empty or hidden filenames
  base = 'file' if base.empty? || base.start_with?('_')
  
  "#{base}#{ext}"
end

    # FIX: Log errors securely without exposing sensitive information
    Rails.logger.error("Backup failed for #{sanitized_filename}: #{e.message}")
    raise
  end
end

  # FIX: Pass unique filename to make_backup for consistent handling
  make_backup(unique_filename, data_path, full_file_name) if backup == "true"
  unique_filename
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
