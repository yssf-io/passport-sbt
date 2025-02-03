import { expect } from "chai";
import { ethers } from "hardhat";
import { ZeroAddress } from "ethers";
import { MockImplRoot } from "../../typechain-types";

describe("ImplRoot", () => {
    let mockImplRoot: MockImplRoot;
    let owner: any;
    let user1: any;

    beforeEach(async () => {
        [owner, user1] = await ethers.getSigners();
        
        const MockImplRootFactory = await ethers.getContractFactory("MockImplRoot", owner);
        mockImplRoot = await MockImplRootFactory.deploy();
        await mockImplRoot.waitForDeployment();
    });

    describe("Initialization", () => {
        it("should revert when calling __ImplRoot_init outside initialization phase", async () => {
            await expect(
                mockImplRoot.exposed__ImplRoot_init()
            ).to.be.revertedWithCustomError(mockImplRoot, "NotInitializing");
        });

        it("should revert when initializing with zero address owner", async () => {
            await expect(
                mockImplRoot.exposed__Ownable_init(ZeroAddress)
            ).to.be.revertedWithCustomError(mockImplRoot, "OwnableInvalidOwner")
            .withArgs(ZeroAddress);
        });

        it("should set correct owner when initializing with valid address", async () => {
            await mockImplRoot.exposed__Ownable_init(owner.address);
            expect(await mockImplRoot.owner()).to.equal(owner.address);
        });

        it("should revert when initializing twice", async () => {
            await mockImplRoot.exposed__Ownable_init(owner.address);
            
            await expect(
                mockImplRoot.exposed__Ownable_init(owner.address)
            ).to.be.revertedWithCustomError(mockImplRoot, "InvalidInitialization");
        });
    });

    describe("Upgrade Authorization", () => {
        let proxy: any;
        let implContract: any;

        beforeEach(async () => {
            const MockImplRootFactory = await ethers.getContractFactory("MockImplRoot", owner);
            implContract = await MockImplRootFactory.deploy();
            await implContract.waitForDeployment();

            const initData = implContract.interface.encodeFunctionData("exposed__Ownable_init", [owner.address]);
            
            const ProxyFactory = await ethers.getContractFactory("ERC1967Proxy");
            proxy = await ProxyFactory.deploy(
                implContract.target,
                initData
            );
            await proxy.waitForDeployment();

            mockImplRoot = await ethers.getContractAt("MockImplRoot", proxy.target);
        });

        it("should revert when calling _authorizeUpgrade from non-proxy", async () => {
            const MockImplRootFactory = await ethers.getContractFactory("MockImplRoot", owner);
            const newImpl = await MockImplRootFactory.deploy();
            await newImpl.waitForDeployment();

            await expect(
                implContract.exposed_authorizeUpgrade(newImpl.target)
            ).to.be.revertedWithCustomError(implContract, "UUPSUnauthorizedCallContext");
        });

        it("should revert when non-owner calls _authorizeUpgrade", async () => {
            const MockImplRootFactory = await ethers.getContractFactory("MockImplRoot", owner);
            const newImpl = await MockImplRootFactory.deploy();
            await newImpl.waitForDeployment();

            await expect(
                mockImplRoot.connect(user1).exposed_authorizeUpgrade(newImpl.target)
            ).to.be.revertedWithCustomError(mockImplRoot, "OwnableUnauthorizedAccount")
            .withArgs(user1.address);
        });

        it("should allow owner to call _authorizeUpgrade through proxy", async () => {
            const MockImplRootFactory = await ethers.getContractFactory("MockImplRoot", owner);
            const newImpl = await MockImplRootFactory.deploy();
            await newImpl.waitForDeployment();

            await expect(
                mockImplRoot.connect(owner).exposed_authorizeUpgrade(newImpl.target)
            ).to.not.be.reverted;
        });
    });
}); 