provides :system_policy
property :instance_name, String, name_property: true
property :policies, Hash, default: {}

default_action :apply

def already_expired?(exp_date)
  # Parse exp date to ruby date format
  excp_validity = begin
                    Date.parse(exp_date)
                  rescue
                    nil
                  end
  if excp_validity.nil?
    Chef::Log.info("Unable to pase expiration date #{exp_date}; Please ensure the date is in 'yyyy-mm-dd' format")
    true
  else
    # Comparing dates will return -1 if first date is less than second one
    -1.equal?(excp_validity <=> DateTime.now)
  end
end

def valid_machine_exception
  # Empty hash to hold return variable with exceptions if any
  ret_machine_exceptions = {}
  # lowercase name for machine
  m_lc_name = node.name
  # load exception data bag for this machine
  m_exception = Chef::Search::Query.new.search('win_security_policy_machine_exception', "id:#{m_lc_name}").first.first
  # if exceptions found, check their validity
  unless m_exception.nil?
    Chef::Log.info("Found exceptions for machine #{m_lc_name}; Checking their validity")
    # Check exception validity
    m_exception.each do |setting_name, exception_data|
      # if no setting override value or expiration time is provided, exception is maked as invalid, continue to next
      unless exception_data['override_value'].nil? || exception_data['exception_valid_until'].nil?
        if already_expired?(exception_data['exception_valid_until'])
          Chef::Log.warn("#{m_lc_name} exception for setting '#{setting_name}' is expired or expiration date is invalid")
        else
          # add exception to the return hash variable for further operation
          ret_machine_exceptions[setting_name] = exception_data['override_value']
        end
      end
    end
  end
  # return all machine exceptions back
  ret_machine_exceptions
end

def valid_role_exception
  # Empty hash to hold return variable with exceptions if any
  ret_role_exceptions = {}
  # retrieve all roles assigned to the machine
  node['roles'].each do |role|
    r_exception = Chef::Search::Query.new.search('win_security_policy_role_exception', "id:#{role}").first.first
    # if exceptions found, check their validity
    next if r_exception.nil?
    Chef::Log.info("Found exceptions for role #{role}; Checking their validity")
    # Check exception validity
    r_exception.each do |setting_name, exception_data|
      # if no setting override value or expiration time is provided, exception is maked as invalid, continue to next
      unless exception_data['override_value'].nil? || exception_data['exception_valid_until'].nil?
        if already_expired?(exception_data['exception_valid_until'])
          Chef::Log.warn("#{role} exception for setting '#{setting_name}' is expired or expiration date is invalid")
        else
          # add exception to the return hash variable for further operation
          ret_role_exceptions[setting_name] = exception_data['override_value']
        end
      end
    end
  end
  ret_role_exceptions
end

action :apply do
  # cache admx linking from databag
  node.run_state['cached_admx_settings'] = data_bag_item('win_server_security_standards', 'supported_admx_regset') if node.run_state['cached_admx_settings'].nil?
  # assign admx linking to variable
  all_available_admx_settings = node.run_state['cached_admx_settings']
  # cache machine excepotions once
  node.run_state['cached_machine_exceptions'] = valid_machine_exception if node.run_state['cached_machine_exceptions'].nil?
  # cache role excepotions once
  node.run_state['cached_role_exceptions'] = valid_role_exception if node.run_state['cached_role_exceptions'].nil?
  # merge machine exceptions with role exceptions
  all_policy_exceptions = node.run_state['cached_machine_exceptions'].merge(node.run_state['cached_role_exceptions'])
  new_resource.policies.each do |setting_name, value|
    specific_admx_setting = all_available_admx_settings[setting_name]
    # activating exception for setting name if available
    unless all_policy_exceptions[setting_name].nil?
      Chef::Log.info("Due to active exceptions, value for '#{setting_name}' will chaneg from #{value} to #{all_policy_exceptions[setting_name]}")
      # change policy best practice value to overriden value as specified in the exception
      value = all_policy_exceptions[setting_name]
    end
    if specific_admx_setting.nil?
      Chef::Log.warn("ADMX linking for #{setting_name} has not been found. The policy will not be applied.")
    else
      # special case for reg_multi_sz (multi string), an input must be an array even if empty or contains only one value
      if specific_admx_setting['control_key_type'] == 'multi_string'
        value_allowed = value.is_a?(Array)
        any_value_ok = value_allowed
      else
        # if allowed values are configured for this registry key, are we trying to set allowed value?
        begin
          value_allowed = specific_admx_setting['control_allowed_values'].include? value
        rescue
          true
        end
        # if no allowed values are configured, assume any value is ok to set
        any_value_ok = specific_admx_setting['control_allowed_values'].nil?
      end
      if value_allowed || any_value_ok
        Chef::Log.info("Setting \"#{setting_name}\" by configuring #{specific_admx_setting['control_registry_key']}\\[#{specific_admx_setting['control_registry_value_name']}] of type \"#{specific_admx_setting['control_key_type']}\" to #{value}")
        registry_key setting_name do
          key specific_admx_setting['control_registry_key']
          values [name: specific_admx_setting['control_registry_value_name'], type: specific_admx_setting['control_key_type'].to_sym, data: value]
          recursive true
          action :create
          ignore_failure true
        end
      else
        Chef::Log.warn("Trying to set invalid value #{value} for #{setting_name}, allowed values #{specific_admx_setting['control_allowed_values']}. This policy will not be set")
      end
    end
  end
end
