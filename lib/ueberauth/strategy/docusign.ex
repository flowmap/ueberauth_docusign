defmodule Ueberauth.Strategy.Docusign do

  use Ueberauth.Strategy, uid_field: :account_id,
                          oauth2_module: Ueberauth.Strategy.Docusign.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Strategy.Docusign.OAuth

  def handle_request!(conn) do
    opts = [redirect_uri: callback_url(conn)]
    |> with_state_param(conn)
    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code,
                                         redirect_uri: callback_url(conn)]])

    case token.access_token do
      nil ->
        set_errors!(conn, [error(token.other_params["error"],
                              token.other_params["error_description"])])
      _ ->
        fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:docusign_user, nil)
    |> put_private(:docusign_token, nil)
  end

  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string
    conn.private.docusign_user[user]
  end

  def credentials(conn) do
    token = conn.private.docusign_token

    %Credentials{
      token: token.access_token,
      token_type: token.token_type,
    }
  end

  def info(conn) do
    user = conn.private.docusign_user

    %Info{
      name: user["name"]["display_name"],
      first_name: user["name"]["given_name"],
      last_name: user["name"]["surname"],
      nickname: user["name"]["familiar_name"],
      email: %{
        email: user["email"],
        email_verified: user["email_verified"]
      },
      location: user["country"],
      urls: %{
        avatar_url: user["profile_photo_url"],
      },
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.docusign_token,
        user: conn.private.docusign_user,
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :docusign_token, token)

    case OAuth.post(token, "/users/get_current_account") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: _status_code, body: user}} ->
        put_private(conn, :docusign_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("Oauth2", reason)])
      _ ->
        set_errors!(conn, [error("error", "Some error occured")])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
