class ManageIQ::Providers::DummyProvider::CloudManager < ManageIQ::Providers::CloudManager
  require_nested :Refresher
  require_nested :RefreshWorker
  require_nested :Vm

  def verify_credentials(auth_type = nil, options = {})
    begin
      connect
    rescue => err
      raise MiqException::MiqInvalidCredentialsError, err.message
    end

    true
  end

  def connect(options = {})
    raise MiqException::MiqHostError, "No credentials defined" if missing_credentials?(options[:auth_type])

    auth_token = authentication_token(options[:auth_type])
    self.class.raw_connect(project, auth_token, options, options[:proxy_uri] || http_proxy_uri)
  end

  def self.validate_authentication_args(params)
    # return args to be used in raw_connect
    return [params[:default_userid], MiqPassword.encrypt(params[:default_password])]
  end

  def self.hostname_required?
    # TODO: ExtManagementSystem is validating this
    false
  end

  def self.raw_connect(*args)
    true
  end

  def self.ems_type
    @ems_type ||= "dummy_provider".freeze
  end

  def self.description
    @description ||= "Dummy Provider".freeze
  end

#### extracted from ems_common_angular.rb ###
# EmsCommonAngular::*
# most of the code can be moved to the concerning provider. What we can do is to list what kind of auth types we
# already built and new provider can re-use those that are already done.
# we can move common parts to parent class


  def populate_record(params, _session, mode = nil)
    self.name                   = params[:name].strip if params[:name]
    self.provider_region        = params[:provider_region]
    self.api_version            = params[:api_version].strip if params[:api_version]
    self.provider_id            = params[:provider_id]
    self.zone                   = Zone.find_by_name(params[:zone])

    endpoints = {
      :default =>  {
        :role              => :default,
        :hostname          => params[:default_hostname].try(:strip),
        :port              => params[:default_api_port].try(:strip),
        :security_protocol => params[:default_security_protocol].try(:strip),
      }
    }

    options = {}
    if self.respond_to?(:advanced_settings)
      self.advanced_settings.each do |section_name, section|
        section[:settings].each do |opt, _|
          options[section_name.to_sym] ||= {}
          value = params["provider_options_#{section_name}_#{opt}".to_sym]
          options[section_name.to_sym][opt.to_sym] = value if value.present?
        end
      end
    end
    if self.respond_to?(:proxy_settings)
      options[:proxy_settings] = {}
      self.proxy_settings.each do |opt, _|
        value = params["provider_options_proxy_settings_#{opt}".to_sym]
        options[:proxy_settings][opt] = value if value.present?
      end
    end

    authentications = build_credentials(mode, params)
    self.connection_configurations = [build_configuration(authentications, endpoints, :default)]
  end

  def build_credentials(mode, params)
    # called from UI
    # params coming from UI

    creds = {}
    if params[:default_userid]
      default_password = params[:default_password] ? params[:default_password] : authentication_password
      creds[:default] = {:userid => params[:default_userid], :password => default_password, :save => (mode != :validate)}
    end
    creds
  end

  def build_configuration(authentications, endpoints, role)
    authtype = role == :default ? default_authentication_type.to_sym : role
    return {:endpoint => endpoints[role], :authentication => nil} unless authentications[authtype]

    authentication = authentications.delete(authtype)
    authentication[:role] = authtype.to_s
    authentication[:authtype] = authtype.to_s
    {:endpoint => endpoints[role], :authentication => authentication}
  end

  private :build_credentials, :build_configuration
end
