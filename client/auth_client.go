package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/x-t4m-cx/common-grpc-auth/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"net/http"
)

type GRPCClient struct {
	client gen.AuthServiceClient
	conn   *grpc.ClientConn
}

func New(authServiceAddr string) (*GRPCClient, error) {
	conn, err := grpc.Dial(authServiceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to auth service: %w", err)
	}

	return &GRPCClient{
		client: gen.NewAuthServiceClient(conn),
		conn:   conn,
	}, nil
}

func (c *GRPCClient) Login(ctx context.Context, username, password string) (*http.Response, error) {
	resp, err := c.client.Login(ctx, &gen.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, convertGRPCError(err)
	}

	httpResp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	httpResp.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	httpResp.Header.Set("Set-Cookie",
		"refresh_token="+resp.RefreshToken+"; HttpOnly; Path=/")

	return httpResp, nil
}

type AuthError struct {
	Message string
	Code    int
}

func (e *AuthError) Error() string {
	return e.Message
}
func (c *GRPCClient) Logout(ctx context.Context) (*http.Response, error) {
	refreshToken := ""
	if ctx.Value("refresh_token") != nil {
		refreshToken = ctx.Value("refresh_token").(string)
	}

	_, err := c.client.Logout(ctx, &gen.LogoutRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return nil, convertGRPCError(err)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Set-Cookie": []string{"refresh_token=; Max-Age=0; HttpOnly; Path=/"},
		},
	}, nil
}

func (c *GRPCClient) Register(ctx context.Context, username, password string) (*http.Response, error) {
	_, err := c.client.Register(ctx, &gen.RegisterRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, convertGRPCError(err)
	}

	return &http.Response{
		StatusCode: http.StatusCreated,
	}, nil
}

func (c *GRPCClient) Refresh(ctx context.Context, refreshToken string) (*http.Response, error) {
	resp, err := c.client.Refresh(ctx, &gen.RefreshRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return nil, convertGRPCError(err)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Authorization": []string{"Bearer " + resp.AccessToken},
			"Set-Cookie":    []string{fmt.Sprintf("refresh_token=%s; HttpOnly; Path=/", resp.RefreshToken)},
		},
	}, nil
}

func (c *GRPCClient) VerifyToken(ctx context.Context, token string) (string, error) {
	resp, err := c.client.VerifyToken(ctx, &gen.VerifyTokenRequest{
		Token: token,
	})
	if err != nil {
		return "", convertGRPCError(err)
	}

	if !resp.Valid {
		return "", errors.New(resp.Error)
	}

	return resp.Username, nil
}

func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

func convertGRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.Unauthenticated:
		return fmt.Errorf("authentication failed: %s", st.Message())
	case codes.AlreadyExists:
		return fmt.Errorf("resource already exists: %s", st.Message())
	case codes.NotFound:
		return fmt.Errorf("resource not found: %s", st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("invalid argument: %s", st.Message())
	default:
		return fmt.Errorf("rpc error: %s", st.Message())
	}
}
