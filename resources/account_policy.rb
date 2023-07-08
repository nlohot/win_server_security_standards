provides :account_policy
property :instance_name, String, name_property: true
property :policies, Hash, default: {}

default_action :apply

action :apply do
  Dir.chdir(Chef::Config['file_cache_path'].to_s) do
    system('secedit /export /cfg secedit_current.inf /areas SecurityPolicy /quiet')
  end

  line_out = []

  ::File.open("#{Chef::Config['file_cache_path']}/secedit_current.inf", 'rb:UTF-16LE:UTF-8') do |file|
    file.each do |line|
      new_line = ''
      new_resource.policies.each do |key, value|
        if line.start_with?(key.to_s)
          new_line = "#{key} = #{value}\r\n"
          puts "updating: #{new_line.gsub("\r\n", '')}"
          break
        else
          new_line = line
        end
      end
      line_out.push new_line.encode('UTF-16LE')
      new_resource.ignore_failure true
    end
  end

  ::File.open("#{Chef::Config['file_cache_path']}/secedit_new.inf", 'wb+') do |f|
    f.puts(line_out)
  end

  Dir.chdir(Chef::Config['file_cache_path'].to_s) do
    system('secedit /configure /db c:\\windows\\securiy\\new.sdb /cfg secedit_new.inf /areas SecurityPolicy /quiet')
  end
end
