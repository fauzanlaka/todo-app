<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\Hash;

// use Illuminate\Support\Facades\Auth;
// use Carbon\Carbon;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        sleep(1);
        $http = new \GuzzleHttp\Client;

        try {
            $response = $http->post(config('services.passport.login_endpoint'), [
            //$response = $http->post('http://127.0.0.1:8001/oauth/token', [
                'form_params' => [
                    'grant_type' => 'password',
                    'client_id' => config('services.passport.client_id'),
                    'client_secret' => config('services.passport.client_secret'),
                    'username' => $request->username,
                    'password' => $request->password,
                ]
            ]);
            return $response->getBody();
        } catch (\GuzzleHttp\Exception\BadResponseException $e) {
            if ($e->getCode() === 400) {
                return response()->json('Invalid Request. Please enter a username or a password.', $e->getCode());
            } else if ($e->getCode() === 401) {
                // return response()->json('Your credentials are incorrect. Please try again', $e->getCode());
                return response()->json('Username Or Password incorrect', $e->getCode());
            }

            return response()->json('Something went wrong on the server.', $e->getCode());
        }

        // $request->validate([
        //     'email' => 'required|string',
        //     'password' => 'required|string',
        //     'remember_me' => 'boolean'
        // ]);
        // $credentials = Request(['email', 'password']);
        // if(!Auth::attempt($credentials))
        //     return response()->json([
        //         'message' => 'Unauthorized'
        //     ], 401);
        // $user = $request->user();
        // $tokenResult = $user->createToken('Personal Access Token');
        // $token = $tokenResult->token;
        // if ($request->remember_me)
        //     $token->expires_at = Carbon::now()->addWeeks(1);
        // $token->save();
        // return response()->json([
        //     'access_token' => $tokenResult->accessToken,
        //     'token_type' => 'Bearer',
        //     'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        // ]);

        
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        return User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
    }

    public function logout()
    {
        auth()->user()->tokens->each(function ($token, $key) {
            $token->delete();
        });

        return response()->json('Logged out successfully', 200);
        // return auth()->user();
    }

    // public function user(Request $request)
    // {
    //     return response()->json($request->user());
    // }
}
