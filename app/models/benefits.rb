# frozen_string_literal: true
class Benefits < ApplicationRecord

def self.save(file, backup = false)
  data_path = Rails.root.join("public", "data")
  # Sanitize the filename to prevent directory traversal
  safe_filename = File.basename(file.original_filename)
  full_file_name = File.join(data_path, safe_filename)
  
  # Ensure the resulting path is within the intended directory
  unless full_file_name.start_with?(data_path.to_s)
    raise SecurityError, "Attempted directory traversal attack"
  end
  
  # Create directory if it doesn't exist
  FileUtils.mkdir_p(data_path) unless File.directory?(data_path)
  
  f = File.open(full_file_name, "wb+")
  f.write file.read
  f.close
  make_backup(file, data_path, full_file_name) if backup == "true"
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
