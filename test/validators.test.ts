import { runWithContext, ValidationError } from '@ghuri/core'
import { describe, expect, it } from 'vitest'
import {
  CommonPasswordValidator,
  getDefaultPasswordValidators,
  MinimumLengthValidator,
  NumericPasswordValidator,
  passwordValidatorsHelpTexts,
  UserAttributeSimilarityValidator,
  validatePassword,
} from '../src/index'
import { quickRatio } from '../src/password-validation'
import { bareContext } from './helpers'

async function errors(p: Promise<unknown>): Promise<string[]> {
  try {
    await p
    return []
  } catch (err) {
    if (err instanceof ValidationError) return err.messages
    throw err
  }
}

describe('password validators', () => {
  it('MinimumLengthValidator', async () => {
    const v = new MinimumLengthValidator({ minLength: 9 })
    expect(() => v.validate('12345678')).toThrow('at least 9 characters')
    expect(() => v.validate('123456789')).not.toThrow()
    expect(new MinimumLengthValidator().minLength).toBe(8)
    expect(new MinimumLengthValidator({ minLength: 1 }).getHelpText()).toBe(
      'Your password must contain at least 1 character.',
    )
  })

  it('CommonPasswordValidator', () => {
    const v = new CommonPasswordValidator()
    expect(() => v.validate('Password')).toThrow('This password is too common.')
    expect(() => v.validate(' qwerty123 ')).toThrow()
    expect(() => v.validate('correct horse battery staple')).not.toThrow()
    expect(() => new CommonPasswordValidator({ passwords: ['Hunter3'] }).validate('hunter3')).toThrow()
  })

  it('NumericPasswordValidator', () => {
    const v = new NumericPasswordValidator()
    expect(() => v.validate('12345678901')).toThrow('entirely numeric')
    expect(() => v.validate('1234a')).not.toThrow()
  })

  it('UserAttributeSimilarityValidator (difflib quick_ratio semantics)', () => {
    expect(quickRatio('abcd', 'bcde')).toBeCloseTo(0.75)
    const v = new UserAttributeSimilarityValidator()
    const user = {
      username: 'testclient',
      email: 'testclient@example.com',
      firstName: 'Test',
      lastName: 'Client',
      constructor: {
        _meta: { getField: (n: string) => ({ verboseName: n === 'email' ? 'email address' : n }) },
      },
    }
    expect(() => v.validate('testclient', user)).toThrow('too similar to the username')
    expect(() => v.validate('example.com', user)).toThrow('too similar to the email address')
    expect(() => v.validate('a completely different passphrase', user)).not.toThrow()
    expect(() => v.validate('testclient')).not.toThrow()
    expect(() => new UserAttributeSimilarityValidator({ maxSimilarity: 0.05 })).toThrow(RangeError)
    expect(() =>
      new UserAttributeSimilarityValidator({ maxSimilarity: 1 }).validate('testclient', user),
    ).toThrow()
  })

  it('validatePassword collects messages from AUTH_PASSWORD_VALIDATORS', async () => {
    const ctx = bareContext({
      AUTH_PASSWORD_VALIDATORS: [
        { NAME: MinimumLengthValidator, OPTIONS: { minLength: 12 } },
        CommonPasswordValidator,
        new NumericPasswordValidator(),
      ],
    })
    await runWithContext(ctx, async () => {
      expect(getDefaultPasswordValidators()).toHaveLength(3)
      expect(await errors(validatePassword('123456'))).toEqual([
        'This password is too short. It must contain at least 12 characters.',
        'This password is too common.',
        'This password is entirely numeric.',
      ])
      expect(await errors(validatePassword('a long and unusual pass phrase'))).toEqual([])
      expect(passwordValidatorsHelpTexts()).toHaveLength(3)
    })
    await runWithContext(bareContext(), async () => {
      expect(getDefaultPasswordValidators()).toEqual([])
      expect(await errors(validatePassword('1'))).toEqual([])
    })
  })
})
