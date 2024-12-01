<?php

namespace App\Http\Controllers\Api\V1;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);
        // dd( $validator);
   
        // Return validation errors if any
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = User::create([
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Securely hash the password
        ]);

        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'access_token' => $token,
        ], 201);
    
    }

    public function login(Request $request)
    {
        $request->validate([
            'email'=>['required','string','email'],
            'password'=>['required','string']

        ]);
       
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
