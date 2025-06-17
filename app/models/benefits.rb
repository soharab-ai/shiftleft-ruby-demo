# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  # Implement content-type validation
  content_type = MIME::Types.type_for(file.original_filename).first.to_s
  
  # Whitelist of allowed content types
  allowed_content_types = ['application/pdf', 'application/msword', 
                          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                          'image/jpeg', 'image/png', 'text/plain',
                          'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
  
  unless allowed_content_types.include?(content_type)
    raise "Invalid file type. Allowed types: PDF, DOC, DOCX, JPG, PNG, TXT, XLS, XLSX"
  end
  
  # Generate a UUID for the file
  file_uuid = SecureRandom.uuid
  
  # Extract original file extension
  extension = File.extname(file.original_filename).downcase
  
  # Create a file record in database
  file_record = FileRecord.create!(
    original_filename: file.original_filename,
    uuid: file_uuid,
    content_type: content_type,
    file_size: file.size,
    extension: extension
  )
  
  # Implement UUID-based path obfuscation
  # Use first 2 characters of UUID as directory name for better file distribution
  uuid_directory = file_uuid[0..1]
  
  # Create storage paths (implementing file sandboxing with separate storage area)
  storage_root = Rails.configuration.file_storage_path || Rails.root.join("storage")
  uuid_path = File.join(storage_root, uuid_directory)
  
  # Create directory if it doesn't exist
  FileUtils.mkdir_p(uuid_path) unless File.directory?(uuid_path)
  
  # Set restrictive permissions on the directory
  FileUtils.chmod(0750, uuid_path)
  
  # Full path with UUID as filename
  full_path = File.join(uuid_path, "#{file_uuid}#{extension}")
  
  # Calculate file hash for content-addressable verification
  file_content = file.read
  content_hash = Digest::SHA256.hexdigest(file_content)
  
  # Store the hash in the database record
  file_record.update!(content_hash: content_hash)
  
  # Write the file with proper permissions
  File.open(full_path, "wb") do |f|
    f.write(file_content)
  end
  
  # Set restrictive permissions on the uploaded file
  FileUtils.chmod(0640, full_path)
  
  # Implement cloud storage integration if configured
  if Rails.configuration.use_cloud_storage
    begin
      s3_client = Aws::S3::Client.new(
        region: Rails.configuration.aws_region,
        access_key_id: Rails.configuration.aws_access_key_id,
        secret_access_key: Rails.configuration.aws_secret_access_key
      )
      
      # Upload to S3 bucket
      bucket = Rails.configuration.aws_bucket_name
      s3_key = "#{uuid_directory}/#{file_uuid}#{extension}"
      
      s3_client.put_object(
        bucket: bucket,
        key: s3_key, 
        body: file_content,
        content_type: content_type
      )
      
      # Update record with S3 information
      file_record.update!(
        storage_location: 's3',
        s3_bucket: bucket,
        s3_key: s3_key
      )
    rescue => e
      Rails.logger.error "Failed to upload to S3: #{e.message}"
    end
  end
  
  # Make backup if requested
  make_backup(file_record, file_content) if backup == "true"
  
  # Return the file record id for reference
  file_record.id
end

# Helper method for backups
def self.make_backup(file_record, file_content)
  backup_uuid = SecureRandom.uuid
  backup_dir = Rails.root.join("backups", backup_uuid[0..1])
  
  FileUtils.mkdir_p(backup_dir) unless File.directory?(backup_dir)
  FileUtils.chmod(0750, backup_dir)
  
  backup_path = File.join(backup_dir, "#{backup_uuid}#{file_record.extension}")
  
  File.open(backup_path, "wb") do |f|
    f.write(file_content)
  end
  
  FileUtils.chmod(0640, backup_path)
  
  # Create backup record
  BackupRecord.create!(
    file_record_id: file_record.id,
    backup_path: backup_path,
    created_at: Time.now
  )
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
