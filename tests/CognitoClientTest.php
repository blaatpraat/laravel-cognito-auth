<?php

namespace BlackBits\LaravelCognitoAuth\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Command;
use Aws\Result;
use BlackBits\LaravelCognitoAuth\CognitoClient;
use Illuminate\Support\Facades\Password;
use Mockery;
use PHPUnit\Framework\TestCase;

/**
 * Class CognitoClientTest
 *
 * @package BlackBits\LaravelCognitoAuth\Tests
 *
 * TODO:
 *  sendResetLink,
 *  resetPassword,
 *  inviteUser,
 *  deleteUser,
 *  invalidatePassword,
 *  confirmSignUp,
 *  setUserAttributes,
 *  getUser
 */
class CognitoClientTest extends TestCase
{

    private $clientId = 'boo';
    private $clientSecret = 'far';
    private $poolId = 'zab';

    private $authenticationResultBody = [
        'AuthenticationResult' => [
            'AccessToken' => 'access_token',
            'ExpiresIn' => 3600,
            'IdToken' => 'id_token',
            'NewDeviceMetadata' => [
                'DeviceGroupKey' => 'device_group_key',
                'DeviceKey' => 'device_key'
            ],
            'RefreshToken' => 'refresh_token',
            'TokenType' => 'token_type'
        ],
        'ChallengeName' => 'challenge_name',
        'ChallengeParameters' => [
            'key' => 'value'
        ],
        'Session' => 'session'
    ];

    public function test_successful_authenticate()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $mockedAwsClient->shouldReceive('adminInitiateAuth')->with([
                'AuthFlow'       => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME'     => $email,
                    'PASSWORD'     => $password,
                    'SECRET_HASH'  => $this->computeHash($email),
                ],
                'ClientId'   => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]
        )->andReturn(
            new Result($this->authenticationResultBody)
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->authenticate($email, $password);

        $authenticationResult = $result->get('AuthenticationResult');
        $this->assertNotNull($authenticationResult);
        $this->assertIsArray($authenticationResult);
        $this->assertArrayHasKeys(['AccessToken', 'ExpiresIn', 'TokenType', 'RefreshToken', 'IdToken'], $authenticationResult);
    }

    public function test_authenticate_requires_reset()
    {
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $resetRequiredException = new CognitoIdentityProviderException(
            'Reset required',
            new Command('Authenticate'),
            ['code' => CognitoClient::RESET_REQUIRED]
        );

        $mockedAwsClient->shouldReceive('adminInitiateAuth')->andThrow($resetRequiredException);

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->authenticate('foo@bar.baz', 'foobar');

        $this->assertFalse($result);
    }

    public function test_authenticate_user_not_found()
    {
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $resetRequiredException = new CognitoIdentityProviderException(
            'Reset required',
            new Command('Authenticate'),
            ['code' => CognitoClient::USER_NOT_FOUND]
        );

        $mockedAwsClient->shouldReceive('adminInitiateAuth')->andThrow($resetRequiredException);

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->authenticate('foo@bar.baz', 'foobar');

        $this->assertFalse($result);
    }

    public function test_authenticate_throws_on_unknown_code()
    {
        $unknownErrorCode = 'foo bar';
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $resetRequiredException = new CognitoIdentityProviderException(
            'Reset required',
            new Command('Authenticate'),
            ['code' => $unknownErrorCode]
        );

        $mockedAwsClient->shouldReceive('adminInitiateAuth')->andThrow($resetRequiredException);

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        try{
            $cognitoClient->authenticate('foo@bar.baz', 'foobar');
            $this->fail('CognitoIdentityProviderException should have been thrown');
        }
        catch (CognitoIdentityProviderException $cognitoIdentityProviderException){
            $this->assertEquals($unknownErrorCode, $cognitoIdentityProviderException->getAwsErrorCode());
        }
    }

    public function test_authenticate_new_password_challenge()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';

        $authenticationResultBody = $this->authenticationResultBody;
        $authenticationResultBody['ChallengeName'] = 'NEW_PASSWORD_REQUIRED';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $mockedAwsClient->shouldReceive('adminInitiateAuth')->andReturn(
            new Result($authenticationResultBody)
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->authenticate($email, $password);

        $challengeName = $result->get('ChallengeName');
        $this->assertNotNull($challengeName);
        $this->assertEquals('NEW_PASSWORD_REQUIRED', $challengeName);
    }

    public function test_successful_confirm_password()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';
        $session = 'boofar';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $mockedAwsClient->shouldReceive('AdminRespondToAuthChallenge')->with([
                'ClientId'           => $this->clientId,
                'UserPoolId'         => $this->poolId,
                'Session'            => $session,
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $password,
                    'USERNAME'     => $email,
                    'SECRET_HASH'  => $this->computeHash($email),
                ],
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
            ]
        )->andReturn(
            new Result()
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->confirmPassword($email, $password, $session);
        $this->assertEquals(Password::PASSWORD_RESET, $result);
    }

    public function test_invalid_token_confirm_password()
    {
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);

        $invalidTokenException = new CognitoIdentityProviderException(
            'Invalid token',
            new Command('ConfirmPassword'),
            ['code' => CognitoClient::CODE_MISMATCH]
        );

        $mockedAwsClient->shouldReceive('AdminRespondToAuthChallenge')->andThrow(
            $invalidTokenException
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->confirmPassword('foo@bar.baz', 'foobar', 'session');
        $this->assertEquals(Password::INVALID_TOKEN, $result);
    }

    public function test_expired_token_confirm_password()
    {
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);

        $invalidTokenException = new CognitoIdentityProviderException(
            'Invalid token',
            new Command('ConfirmPassword'),
            ['code' => CognitoClient::EXPIRED_CODE]
        );

        $mockedAwsClient->shouldReceive('AdminRespondToAuthChallenge')->andThrow(
            $invalidTokenException
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->confirmPassword('foo@bar.baz', 'foobar', 'session');
        $this->assertEquals(Password::INVALID_TOKEN, $result);
    }

    public function test_confirm_password_throws_on_unknown_code()
    {
        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $unknownCognitoError = 'foo bar';
        $invalidTokenException = new CognitoIdentityProviderException(
            'Invalid token',
            new Command('ConfirmPassword'),
            ['code' => $unknownCognitoError]
        );

        $mockedAwsClient->shouldReceive('AdminRespondToAuthChallenge')->andThrow(
            $invalidTokenException
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        try{
            $cognitoClient->confirmPassword('foo@bar.baz', 'foobar', 'session');
            $this->fail('CognitoIdentityProviderException should have been thrown');
        }
        catch (CognitoIdentityProviderException $cognitoIdentityProviderException){
            $this->assertEquals($unknownCognitoError, $cognitoIdentityProviderException->getAwsErrorCode());
        }
    }

    public function test_successful_register()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);
        $mockedAwsClient->shouldReceive('signUp')->with([
            'ClientId'       => $this->clientId,
            'Password'       => $password,
            'SecretHash'     => $this->computeHash($email),
            'UserAttributes' => [
                [
                    'Name' => 'foo',
                    'Value' => 'bar'
                ],
                [
                    'Name' => 'email',
                    'Value' => $email
                ]
            ],
            'Username'       => $email,
        ])->andReturn(
            new Result(['UserConfirmed' => true])
        );

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->register($email, $password, ['foo' => 'bar']);
        $this->assertTrue($result);
    }

    public function test_register_fails_on_existing_user()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);

        $usernameExistsException = new CognitoIdentityProviderException(
            'Username exists',
            new Command('signUp'),
            ['code' => CognitoClient::USERNAME_EXISTS]
        );

        $mockedAwsClient->shouldReceive('signUp')->andThrow($usernameExistsException);

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        $result = $cognitoClient->register($email, $password, ['foo' => 'bar']);
        $this->assertFalse($result);
    }

    public function test_register_fails_on_unknown_error()
    {
        $email = 'foo@bar.baz';
        $password = 'foobar';

        $mockedAwsClient = Mockery::mock(CognitoIdentityProviderClient::class);

        $unknownErrorCode = 'foo bar';

        $usernameExistsException = new CognitoIdentityProviderException(
            'Username exists',
            new Command('signUp'),
            ['code' => $unknownErrorCode]
        );

        $mockedAwsClient->shouldReceive('signUp')->andThrow($usernameExistsException);

        $cognitoClient = new CognitoClient(
            $mockedAwsClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );

        try{
            $cognitoClient->register($email, $password, ['foo' => 'bar']);
            $this->fail('CognitoIdentityProviderException was not thrown');
        }
        catch (CognitoIdentityProviderException $cognitoIdentityProviderException){
            $this->assertEquals($unknownErrorCode, $cognitoIdentityProviderException->getAwsErrorCode());
        }
    }

    private function computeHash($email)
    {
        $hash = hash_hmac(
            'sha256',
            $email.$this->clientId,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }

    private function assertArrayHasKeys(array $expectedKeys, array $array)
    {
        foreach ($expectedKeys as $expectedKey){
            $this->assertArrayHasKey($expectedKey, $array);
        }
    }
}