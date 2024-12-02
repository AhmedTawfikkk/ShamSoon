<?php

namespace App\Http\Controllers\Api\V1;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use App\Notifications\EmailVerificationNotification;
use Illuminate\Support\Facades\Hash;

class AuthController
{
    public function register(RegisterRequest $request)
    {
       
        $user = User::create([
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password), 
        ]);

        $token = $user->createToken('authToken')->plainTextToken;
        $user->notify(new EmailVerificationNotification());

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'access_token' => $token,
        ], 201);
    
    }

    public function login(LoginRequest $request)
    {
       
        $user=User::where('email',$request->email)->first();
        if(!$user|| !Hash::check($request->password,$user->password))
        {
            return response()->json(
                [
                    'error'=>'the provided credentials are incorrect'
                ] ,422);
        }
        $device=substr($request->userAgent()??'',0,255);
        return response()->json(
            [
                'access_token'=>$user->CreateToken($device)->plainTextToken,
                'message' => 'Login successful'
            ]
            ,201);
    }
}
