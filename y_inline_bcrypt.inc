#if defined _INC_y_inline_bcrypt
	#endinput
#endif
#define _INC_y_inline_bcrypt

#include <samp_bcrypt>

forward WhenIRageQuitThis(playerid,Func:cb<s>);
forward WhenIShitMyselfRly(playerid,success,Func:cb<i>);

public WhenIRageQuitThis(playerid,Func:cb<s>)
{
    new result[BCRYPT_HASH_LENGTH];
    bcrypt_get_hash(result);

    @.cb(result);
    Indirect_Release(cb);
    return 1;
}

public WhenIShitMyselfRly(playerid,success,Func:cb<i>)
{
    @.cb(success);
    Indirect_Release(cb);
    return 1;
}

BCrypt_HashInline(const password[], cost = BCRYPT_COST, {F@_@s, F@_@si}:cb)
{
    if (bcrypt_hash(0, #WhenIRageQuitThis, password, cost, "i", _:cb))
    {
        Indirect_Claim(cb);
        return 1;
    }
    return 0;
}

bool:BCrypt_CheckInline(const password[], const hash[], Func:cb<i>)
{
    if (bcrypt_verify(0, #WhenIShitMyselfRly, password, hash, "i", _:cb))
    {
        Indirect_Claim(cb);
        return true;
    }
    return false;
}
