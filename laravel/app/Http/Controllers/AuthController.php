<?php

namespace App\Http\Controllers;

use App\Helpers\JwtApi;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Models\Token;
use Exception;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('jwt.verify', ['except' => ['login', 'register']]);
        $this->middleware('jwt.xauth', ['except' => ['login', 'register', 'refresh']]);
        $this->middleware('jwt.xrefresh', ['only' => ['refresh']]);
    }

    public function login(Request $request)
    {
        $credentials = request(['email', 'password']);


        if (!$access_token = auth()->claims(['xtype' => 'auth'])->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($access_token);

    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = Auth::login($user);
        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function logout()
    {
        $refresh_token_obj = Token::findPairByValue(auth()->getToken()->get());
        auth()->logout();
        auth()->setToken($refresh_token_obj->value)->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function logoutall(Request $request){
        foreach( auth()->user()->token as $token_obj ){
          try{
            auth()->setToken( $token_obj->value )->invalidate(true);
          }
          catch (Exception $e){
            //do nothing, it's already bad token for various reasons
          }
        }
   
        return response()->json(['message' => 'Successfully logged out from all devices']);
      }

    public function refresh()
    {
        $access_token = auth()->claims(['xtype' => 'auth'])->refresh(true, true);
        auth()->setToken($access_token);

        return $this->respondWithToken($access_token);
    }

    public function verify_token(Request $request)
    {
        $token = $request->bearerToken();
        // print_r($request->api_token);die;
        if ($token !== $request->api_token) {
            return response()->json('Token fornecido não confere', 401);
        }
        
        return  auth()->user();

    }

    protected function respondWithToken($access_token)
    {
        $response_array = [
            'api_token' => $access_token,
            'token_type' => 'bearer',
            'access_expires_in' => auth()->factory()->getTTL() * 60,
        ];

        $access_token_obj = Token::create([
            'user_id' => auth()->user()->id,
            'value' => $access_token, //or auth()->getToken()->get();
            'jti' => auth()->payload()->get('jti'),
            'type' => auth()->payload()->get('xtype'),
            'payload' => auth()->payload()->toArray(),
            'ip' => JwtApi::getIp(),
            'device' => JwtApi::getUserAgent()
          ]);

        $refresh_token = auth()->claims([
            'xtype' => 'refresh',
            'xpair' => auth()->payload()->get('jti')
        ])->setTTL(auth()->factory()->getTTL() * 3)->tokenById(auth()->user()->id);

        $response_array += [
            'api_token' => $refresh_token,
            'refresh_expires_in' => auth()->factory()->getTTL() * 60
        ];

        $refresh_token_obj = Token::create([
            'user_id' => auth()->user()->id,
            'value' => $refresh_token,
            'jti' => auth()->setToken($refresh_token)->payload()->get('jti'),
            'type' => auth()->setToken($refresh_token)->payload()->get('xtype'),
            'pair' => $access_token_obj->id,
            'payload' => auth()->setToken($refresh_token)->payload()->toArray(),
            'ip' => JwtApi::getIp(),
            'device' => JwtApi::getUserAgent()
          ]);

        $access_token_obj->pair = $refresh_token_obj->id;
        $access_token_obj->save();

        return response()->json($response_array);
    }

    public function me()
    {
        return response()->json(auth()->user());
    }

    public function tokenIssue(Request $request){
        $validate = Validator::make($request->all(), [
          'id' => 'required|boolean',
          'name' => 'required|boolean',
          'email' => 'required|boolean'
        ]);
  
        if ( $validate->fails() ){
          return response()->json(['message' => 'Error! Bad input.'], 400);
        }
  
        $resource_token = auth()->claims([
            'xtype' => 'resource'
          ])->setTTL(60 * 24 * 365)->tokenById(auth()->user()->id); //expire in 1 year
  
        $resource_token_obj = Token::create([
            'user_id' => auth()->user()->id,
            'value' => $resource_token,
            'jti' => auth()->setToken($resource_token)->payload()->get('jti'),
            'type' => auth()->setToken($resource_token)->payload()->get('xtype'),
            'pair' => null,
            'payload' => auth()->setToken($resource_token)->payload()->toArray(),
            'grants' => [
              'id' => $request->input('id'),
              'name' => $request->input('name'),
              'email' => $request->input('email')
            ],
            'ip' => null,
            'device' => null
        ]);  
        return response()->json(['token' => $resource_token]);
      }
}