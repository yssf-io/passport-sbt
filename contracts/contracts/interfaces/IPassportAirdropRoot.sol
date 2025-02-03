// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IPassportAirdropRoot
 * @notice Interface that defines types relevant for the Passport Airdrop Root functionality.
 * @dev This interface currently exposes the VerificationConfig struct used for configuring
 * the verification process during passport airdrop registration.
 */
interface IPassportAirdropRoot {

    /**
     * @notice Configuration settings for the verification process.
     * @dev These settings determine which attributes are enabled for verification and the expected values.
     * @param olderThanEnabled Flag indicating if the 'olderThan' attribute should be verified.
     * @param olderThan The threshold value used for 'olderThan' verification.
     * @param forbiddenCountriesEnabled Flag indicating if the 'forbiddenCountries' attribute should be verified.
     * @param forbiddenCountriesListPacked The packed representation of the forbidden countries list.
     * @param ofacEnabled Flag indicating if the 'ofac' attribute should be verified.
     */
    struct VerificationConfig {
        bool olderThanEnabled;
        uint256 olderThan;
        bool forbiddenCountriesEnabled;
        uint256 forbiddenCountriesListPacked;
        bool ofacEnabled;
    }

}