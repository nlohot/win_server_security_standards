provides :audit_policy
property :instance_name, String, name_property: true
property :policies, Hash, default: {}

default_action :apply

action :apply do
  system('auditpol /clear /y')
  new_resource.policies.each do |key, value|
    setting = key.to_s.tr('_', ' ')
    params = ''
    value.split(',').each do |item|
      params = "/#{item}:enable #{params}"
    end
    command = "auditpol /set /subcategory:\"#{setting}\" #{params} 2>&1"
    converge_by("set #{new_resource.instance_name} policies") do
      system(command)
    end
  end
end
