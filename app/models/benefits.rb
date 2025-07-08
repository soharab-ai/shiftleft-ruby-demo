# frozen_string_literal: true
class Benefits < ApplicationRecord

  def self.save(file, backup = false)
# Define constants for allowed file extensions and MIME types
ALLOWED_EXTENSIONS = %w[.pdf .doc .docx .txt .jpg .png].freeze
ALLOWED_MIME_TYPES = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'image/jpeg', 'image/png'].freeze

def self.save(file, backup = false)
  # Validate content type for improved security
  unless ALLOWED_MIME_TYPES.include?(file.content_type)
    raise "Invalid file type"
  end
# This method is no longer used as we're using BackupService instead
# Keeping it as a wrapper for backward compatibility
def self.make_backup(file, data_path, full_file_name)
  BackupService.perform_backup(full_file_name, file.original_filename)
end

# New BackupService class for handling backups
class BackupService
  # Class method to handle backup operations
  def self.perform_backup(file_path, original_filename)
    if File.exist?(file_path)
      # Use background job for backup operations
      BackupJob.perform_later(file_path, original_filename)
    end
  end
  
  # In a real application, this would be in a separate file
  class BackupJob < ActiveJob::Base
    queue_as :default
    
    def perform(file_path, original_filename)
      # Option 1: Local backup using FileUtils (safer than system commands)
      backup_path = Rails.root.join("public", "data", "backups")
      FileUtils.mkdir_p(backup_path) unless Dir.exist?(backup_path)
      backup_filename = "bak#{Time.zone.now.to_i}_#{SecureRandom.uuid}#{File.extname(original_filename)}"
      FileUtils.cp(file_path, "#{backup_path}/#{backup_filename}")
      
      # Option 2: Cloud storage backup (commented out as it requires configuration)
      # upload_to_cloud_storage(file_path, backup_filename)
    end
    
    private
    
    def upload_to_cloud_storage(file_path, backup_filename)
      # Example implementation for AWS S3
      s3_client = Aws::S3::Client.new(
        region: ENV['AWS_REGION'],
        access_key_id: ENV['AWS_ACCESS_KEY_ID'],
        secret_access_key: ENV['AWS_SECRET_ACCESS_KEY']
      )
      
      s3_client.put_object(
        bucket: ENV['AWS_BUCKET_NAME'],
        key: "backups/#{backup_filename}",
        body: File.read(file_path)
      )
    end
  end
end

  end
  
  # Generate UUID-based filename strategy to avoid relying on user input
  uuid_filename = "#{SecureRandom.uuid}#{original_extension}"
  
  # Store mapping between original filename and UUID (in a real app, this would go to a database)
  @filename_mappings ||= null
  @filename_mappings[uuid_filename] = file.original_filename
  
  data_path = Rails.root.join("public", "data")
  full_file_name = "#{data_path}/#{uuid_filename}"
  
  # Save file with UUID-based name
  f = File.open(full_file_name, "wb+")
  f.write file.read
  f.close
  
  # Use backup service if backup requested
  BackupService.perform_backup(full_file_name, file.original_filename) if backup == "true"
  
  return uuid_filename # Return the UUID filename for reference
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
