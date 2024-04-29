defmodule Ueberauth.Strategy.Docusign.OAuth do

  use OAuth2.Strategy

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    site: "https://api.dropboxapi.com/2",
    authorize_url: "https://www.docusign.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Docusign.OAuth)
    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    json_library = Ueberauth.json_library()

    Client.new(client_opts)
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client()
    |> Client.authorize_url!(params)
  end

  def post(token, url, headers \\ [], opts \\ []) do
    headers = Keyword.put(headers, :"Content-Type", "application/json")
    [token: token]
    |> client()
    |> Client.post(url, nil, headers, opts)
  end

  def get_token!(params \\ [], options \\ []) do
    headers = Keyword.get(options, :headers, [])
    options = Keyword.get(options, :options, [])

    response =
      options
      |> Keyword.get(:client_options, [])
      |> client()
      |> Client.get_token(params, headers, options)

    case response do
      {:ok, client} ->
        client.token
      {:error, error} ->
        %{access_token: nil, other_params: error.body}
    end
  end

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_id", client.client_id)
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> put_param(:grant_type, "authorization_code")
    |> put_param(:redirect_uri, client.redirect_uri)
    |> merge_params(params)
    |> put_headers(headers)
  end
end
