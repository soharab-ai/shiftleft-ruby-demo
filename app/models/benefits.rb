# frozen_string_literal: true
class Benefits < ApplicationRecord

  def self.save(file, backup = false)
    data_path = Rails.root.join("public", "data")
    full_file_name = "#{data_path}/#{file.original_filename}"
    f = File.open(full_file_name, "wb+")
    f.write file.read
    f.close
    make_backup(file, data_path, full_file_name) if backup == "true"
  end

def self.make_backup(file, data_path, full_file_name)
  # Added security logging for all backup attempts
  Rails.logger.info("Backup attempt for file: #{file.original_filename}")
  
  # Validate both filename and content type before proceeding
  unless valid_file?(file)
    # Added security logging for failed validation attempts
    Rails.logger.warn("Potential command injection attempt: #{file.original_filename}")
    return false
  end
  
  if File.exist?(full_file_name)
    # Use Ruby's FileUtils instead of system command to prevent command injection
    backup_filename = "#{data_path}/bak#{Time.zone.now.to_i}_#{File.basename(file.original_filename)}"
    FileUtils.cp(full_file_name, backup_filename)
    return true
  end
  
  false
end

# Added path traversal protection in filename validation
def self.valid_filename?(filename)
  # Normalize the path and ensure it doesn't contain directory traversal
  normalized_path = File.basename(filename)
  return normalized_path == filename && filename =~ /\A[\w\-\.]+\z/
end

# Added allowlist for file extensions
def self.valid_file_extension?(filename)
  allowed_extensions = %w[.pdf .doc .docx .txt .csv]
  extension = File.extname(filename).downcase
  allowed_extensions.include?(extension)
end

# Added content type validation
def self.valid_file?(file)
  valid_content_types = ['application/pdf', 'text/plain', 'application/msword', 
                         'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                         'text/csv']
  
  valid_filename?(file.original_filename) && 
  valid_file_extension?(file.original_filename) && 
  valid_content_types.include?(file.content_type)
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
