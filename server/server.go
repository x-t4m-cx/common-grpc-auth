package server

import (
	"context"
	"errors"
	"github.com/x-t4m-cx/common-grpc-auth/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
type TokenClaims struct {
	UserID   int
	Username string
}

type AuthService interface {
	Register(ctx context.Context, username, password string) error
	Login(ctx context.Context, username, password string) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	VerifyToken(token string) (*TokenClaims, error)
}

var (
	UserNotFound      = errors.New("user not found")
	UserAlreadyExists = errors.New("user already exists")
	InvalidToken      = errors.New("invalid token")
	InvalidData       = errors.New("invalid data")
)

type Server struct {
	gen.UnimplementedAuthServiceServer
	AuthService AuthService
}

func (s *Server) Register(ctx context.Context, req *gen.RegisterRequest) (*gen.RegisterResponse, error) {
	err := s.AuthService.Register(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, UserAlreadyExists) {
			return nil, status.Errorf(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Errorf(codes.Internal, "failed to register user: %v", err)
	}
	return &gen.RegisterResponse{Message: "user created successfully"}, nil
}

func (s *Server) Login(ctx context.Context, req *gen.LoginRequest) (*gen.LoginResponse, error) {
	tokens, err := s.AuthService.Login(ctx, req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, UserNotFound), errors.Is(err, InvalidData):
			return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
		default:
			return nil, status.Errorf(codes.Internal, "failed to login: %v", err)
		}
	}

	return &gen.LoginResponse{
		Message:      "login successful",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *Server) Refresh(ctx context.Context, req *gen.RefreshRequest) (*gen.RefreshResponse, error) {
	tokens, err := s.AuthService.Refresh(ctx, req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, InvalidToken):
			return nil, status.Errorf(codes.Unauthenticated, "invalid token")
		case errors.Is(err, UserNotFound):
			return nil, status.Errorf(codes.Unauthenticated, "user not found")
		default:
			return nil, status.Errorf(codes.Internal, "failed to refresh tokens: %v", err)
		}
	}

	return &gen.RefreshResponse{
		Message:      "tokens refreshed successfully",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *Server) Logout(ctx context.Context, req *gen.LogoutRequest) (*gen.LogoutResponse, error) {
	return &gen.LogoutResponse{Message: "logout successful"}, nil
}

func (s *Server) VerifyToken(ctx context.Context, req *gen.VerifyTokenRequest) (*gen.VerifyTokenResponse, error) {
	claim, err := s.AuthService.VerifyToken(req.Token)
	if err != nil {
		return &gen.VerifyTokenResponse{
			Valid: false,
			Error: "invalid token",
		}, nil
	}

	return &gen.VerifyTokenResponse{
		Valid:    true,
		Username: claim.Username,
	}, nil
}
