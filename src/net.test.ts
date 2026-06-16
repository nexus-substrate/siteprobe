/**
 * Unit tests for address-class classification used by the SSRF guard.
 */
import { describe, it, expect } from 'vitest';
import { classifyAddress, isBlockedAddress } from './net.js';

describe('classifyAddress', () => {
  it('classifies IPv4 loopback', () => {
    expect(classifyAddress('127.0.0.1')).toBe('loopback');
    expect(classifyAddress('127.255.255.254')).toBe('loopback');
  });

  it('classifies IPv6 loopback', () => {
    expect(classifyAddress('::1')).toBe('loopback');
  });

  it('classifies RFC1918 private ranges', () => {
    expect(classifyAddress('10.0.0.1')).toBe('private');
    expect(classifyAddress('192.168.1.1')).toBe('private');
    expect(classifyAddress('172.16.0.1')).toBe('private');
    expect(classifyAddress('172.31.255.255')).toBe('private');
  });

  it('does NOT classify 172.32.x as private', () => {
    expect(classifyAddress('172.32.0.1')).toBe('public');
    expect(classifyAddress('172.15.0.1')).toBe('public');
  });

  it('classifies link-local (incl. cloud metadata 169.254.169.254)', () => {
    expect(classifyAddress('169.254.0.1')).toBe('link-local');
    expect(classifyAddress('169.254.169.254')).toBe('link-local');
  });

  it('classifies IPv6 link-local and unique-local', () => {
    expect(classifyAddress('fe80::1')).toBe('link-local');
    expect(classifyAddress('fc00::1')).toBe('private');
    expect(classifyAddress('fd12:3456::1')).toBe('private');
  });

  it('classifies CGNAT 100.64.0.0/10', () => {
    expect(classifyAddress('100.64.0.1')).toBe('private');
    expect(classifyAddress('100.127.255.255')).toBe('private');
    expect(classifyAddress('100.128.0.1')).toBe('public');
  });

  it('classifies reserved/special ranges', () => {
    expect(classifyAddress('0.0.0.0')).toBe('reserved');
    expect(classifyAddress('240.0.0.1')).toBe('reserved');
  });

  it('classifies public addresses', () => {
    expect(classifyAddress('8.8.8.8')).toBe('public');
    expect(classifyAddress('1.1.1.1')).toBe('public');
    expect(classifyAddress('2606:4700:4700::1111')).toBe('public');
  });

  it('handles IPv4-mapped IPv6', () => {
    expect(classifyAddress('::ffff:127.0.0.1')).toBe('loopback');
    expect(classifyAddress('::ffff:10.0.0.1')).toBe('private');
  });
});

describe('isBlockedAddress', () => {
  it('blocks loopback, private, link-local, reserved by default', () => {
    expect(isBlockedAddress('127.0.0.1', {})).toBe(true);
    expect(isBlockedAddress('10.0.0.1', {})).toBe(true);
    expect(isBlockedAddress('169.254.169.254', {})).toBe(true);
    expect(isBlockedAddress('0.0.0.0', {})).toBe(true);
  });

  it('allows public addresses by default', () => {
    expect(isBlockedAddress('8.8.8.8', {})).toBe(false);
  });

  it('allowLocal re-enables loopback only', () => {
    expect(isBlockedAddress('127.0.0.1', { allowLocal: true })).toBe(false);
    expect(isBlockedAddress('10.0.0.1', { allowLocal: true })).toBe(true);
  });

  it('allowPrivate re-enables private + link-local + loopback', () => {
    expect(isBlockedAddress('10.0.0.1', { allowPrivate: true })).toBe(false);
    expect(isBlockedAddress('169.254.169.254', { allowPrivate: true })).toBe(false);
    expect(isBlockedAddress('127.0.0.1', { allowPrivate: true })).toBe(false);
  });
});
