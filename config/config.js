module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: "Cisco Threat Response",
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: "CTR",
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    "Cisco Threat Response is built upon a collection of APIs which can be used to integrate your Cisco and third-party security products, automate the incident response process, and manage threat intelligence and security context data in a single location.",
  entityTypes: ['IPv4', 'hash', 'domain', 'email'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ["./styles/style.less"],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: "./components/block.js"
    },
    template: {
      file: "./templates/block.hbs"
    }
  },
  summary: {
    component: {
      file: "./components/summary.js"
    },
    template: {
      file: "./templates/summary.hbs"
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the Trustar integration's root directory
    cert: "",
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the Trustar integration's root directory
    key: "",
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the Trustar integration's root directory
    passphrase: "",
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the Trustar integration's root directory
    ca: "",
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: "",

    rejectUnauthorized: false
  },
  logging: {
    level: "trace" //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: "url",
      name: "Base Cisco Threat Response API URL",
      description:
        "The base URL for the Cisco Threat Response API including the schema (i.e., https://)",
      type: "text",
      default: "https://visibility.amp.cisco.com",
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: "clientId",
      name: "Valid Client ID",
      description: "Valid Cisco Threat Response Client ID",
      default: "",
      type: "password",
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: "clientPassword",
      name: "Valid Client Password",
      description: "Valid Cisco Threat Response Client Password",
      default: "",
      type: "password",
      userCanEdit: true,
      adminOnly: false
    }
  ]
};
